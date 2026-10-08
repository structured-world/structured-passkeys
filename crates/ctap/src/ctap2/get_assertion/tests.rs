//! authenticatorGetAssertion and authenticatorGetNextAssertion against CTAP 2.2 §6.2.2 and §6.3,
//! end to end through the authenticator. Signatures are checked here with the RustCrypto crates
//! against the public keys the registrations returned.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use sha2::{Digest, Sha256};

use super::super::client_pin::tests::{Value, command, hmac, parse_response, run, uv_token};
use super::super::make_credential::tests::{
    BE, BS, CLIENT_DATA_HASH, Made, OK, RP_ID, UP, UV, descriptors, options, register, verifies,
};
use super::super::tests::{
    Asked, Scripted, Shown, TestAuthenticator, authenticator, authenticator_with,
};
use super::super::{Authenticator, Link, NfcTap, Transports};
use super::NEXT_ASSERTION_TIMEOUT_MS;
use crate::cbor::{Decoder, Key};
use crate::credential_id::Origin;
use crate::crypto::KEY_LEN;
use crate::pin::MAX_USAGE_TIME_PERIOD_MS;
use crate::soft::SoftCrypto;
use crate::storage::{MemoryStorage, Store};
use crate::ui::{
    Accounts, Answer, Choice, Passkeys, Prompt, Registration, USER_ACTION_TIMEOUT_MS, Ui,
};

const OPERATION_DENIED: u8 = 0x27;
const UNSUPPORTED_OPTION: u8 = 0x2B;
const KEEPALIVE_CANCEL: u8 = 0x2D;
const NO_CREDENTIALS: u8 = 0x2E;
const NOT_ALLOWED: u8 = 0x30;
const PIN_AUTH_INVALID: u8 = 0x33;

/// What a getAssertion response holds.
#[derive(Debug, Default)]
struct Asserted {
    id: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    /// `user` as `(id, name, displayName)`.
    user: Option<(Vec<u8>, Option<String>, Option<String>)>,
    number_of_credentials: Option<u64>,
    user_selected: Option<bool>,
}

impl Asserted {
    fn flags(&self) -> u8 {
        self.auth_data[32]
    }

    /// Whether the signature verifies under `made`'s key over authenticatorData ||
    /// clientDataHash (WebAuthn L3 §6.3.3 step 11).
    fn signed_by(&self, made: &Made) -> bool {
        let mut signed = self.auth_data.clone();
        signed.extend_from_slice(&CLIENT_DATA_HASH);
        self.id == made.id && verifies(&made.public_key, &signed, &self.signature)
    }
}

fn asserted(body: &[u8]) -> Asserted {
    let mut decoder = Decoder::new(body);
    let asserted = decoder
        .map(|entries| {
            let mut asserted = Asserted::default();
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => {
                        asserted.id = value.map(|members| {
                            let mut id = Vec::new();
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("id") => id = member.bytes()?.to_vec(),
                                    Key::Text("type") => assert_eq!(member.text()?, "public-key"),
                                    _ => panic!("unexpected descriptor member"),
                                }
                            }
                            Ok(id)
                        })?;
                    }
                    Key::Int(2) => asserted.auth_data = value.bytes()?.to_vec(),
                    Key::Int(3) => asserted.signature = value.bytes()?.to_vec(),
                    Key::Int(4) => {
                        asserted.user = Some(value.map(|members| {
                            let mut user = (Vec::new(), None, None);
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("id") => user.0 = member.bytes()?.to_vec(),
                                    Key::Text("name") => user.1 = Some(member.text()?.into()),
                                    Key::Text("displayName") => {
                                        user.2 = Some(member.text()?.into());
                                    }
                                    _ => panic!("unexpected user member"),
                                }
                            }
                            Ok(user)
                        })?);
                    }
                    Key::Int(5) => asserted.number_of_credentials = Some(value.unsigned()?),
                    Key::Int(6) => asserted.user_selected = Some(value.bool()?),
                    _ => panic!("unexpected response member"),
                }
            }
            Ok(asserted)
        })
        .expect("a response map");
    decoder.finish().expect("one item");
    assert_eq!(asserted.auth_data.len(), 37, "no attested credential data");
    assert_eq!(asserted.auth_data[..32], Sha256::digest(RP_ID)[..]);
    assert_eq!(
        asserted.auth_data[33..],
        [0, 0, 0, 0],
        "signature counter 0"
    );
    asserted
}

/// A getAssertion for `RP_ID` with `allow_list` and options `opts`.
fn assertion(allow_list: Option<&[&[u8]]>, opts: &[(&str, bool)]) -> Vec<u8> {
    let mut members = vec![
        (0x01, Value::Text(RP_ID)),
        (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
    ];
    if let Some(ids) = allow_list {
        members.push((0x03, descriptors(ids)));
    }
    members.push((0x05, options(opts)));
    command(0x02, &members)
}

/// Runs `request` for a user who answers `answer` and picks `pick`.
fn assert_with(
    authenticator: &mut TestAuthenticator,
    request: &[u8],
    answer: Answer,
    pick: usize,
) -> (Vec<u8>, Vec<(Asked, u32)>) {
    let mut ui = Scripted::new(answer);
    ui.pick = pick;
    let response = run(authenticator, &mut ui, request);
    (response, ui.asked)
}

/// A non-discoverable credential signs an assertion when its ID is in the allowList, after the
/// user confirms on the screen, which names the RP and the key origin; the authenticator data has
/// UP, no UV (none was asked for), BE and BS of the seed-recoverable origin and a counter of 0,
/// and the response carries no `user` (§6.2.2 steps 11, 15.3, 16).
#[test]
fn an_allow_list_credential_signs_after_confirmation() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let (response, asked) = assert_with(
        &mut authenticator,
        &assertion(Some(&[&[1, 2, 3], &made.id]), &[]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    let asserted = asserted(&response[1..]);
    assert!(asserted.signed_by(&made));
    assert_eq!(asserted.flags(), UP | BE | BS);
    assert!(asserted.user.is_none());
    assert_eq!(asserted.number_of_credentials, None);
    assert_eq!(
        asked,
        [(
            Asked::Assertion {
                rp_id: String::from(RP_ID),
                account: Shown {
                    name: None,
                    display_name: None,
                    origin: Some(Origin::SeedRecoverable),
                },
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
}

/// A refusal or no answer on the screen is CTAP2_ERR_OPERATION_DENIED, a cancel
/// CTAP2_ERR_KEEPALIVE_CANCEL (§6.2.2 step 11.2.1.2, §11.2.9.1.5).
#[test]
fn a_refused_assertion_signs_nothing() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    for (answer, status) in [
        (Answer::Rejected, OPERATION_DENIED),
        (Answer::TimedOut, OPERATION_DENIED),
        (Answer::Cancelled, KEEPALIVE_CANCEL),
    ] {
        let (response, _) = assert_with(
            &mut authenticator,
            &assertion(Some(&[&made.id]), &[]),
            answer,
            0,
        );
        assert_eq!(response, [status], "{answer:?}");
    }
}

/// With the uv option, built-in user verification (the device unlock) sets UV; a discoverable
/// credential then returns its user with the names, which without UV are left out, the handle
/// alone (§6.2.2 step 15.3). A device-only key has neither BE nor BS.
#[test]
fn a_discoverable_credential_returns_its_user() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", true, None);
    let (response, asked) = assert_with(
        &mut authenticator,
        &assertion(None, &[]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    let plain = asserted(&response[1..]);
    assert!(plain.signed_by(&made));
    assert_eq!(plain.flags(), UP, "device-only, no UV");
    assert_eq!(plain.user, Some((b"user-1".to_vec(), None, None)));
    assert!(matches!(
        &asked[..],
        [(Asked::Assertion { account, .. }, _)]
            if account.name.as_deref() == Some("alice")
                && account.origin == Some(Origin::DeviceOnly)
    ));

    let (response, _) = assert_with(
        &mut authenticator,
        &assertion(None, &[("uv", true)]),
        Answer::Confirmed,
        0,
    );
    let verified = asserted(&response[1..]);
    assert_eq!(verified.flags(), UP | UV);
    assert_eq!(
        verified.user,
        Some((
            b"user-1".to_vec(),
            Some(String::from("alice")),
            Some(String::from("Alice"))
        ))
    );
}

/// Several discoverable credentials for the RP and a request that asks for presence: the device
/// lists the accounts, most recently created first, with their key origins, and the one the user
/// picks signs; the response says `userSelected` and gives no count (§6.2.2 step 15.2.3). A
/// refusal is CTAP2_ERR_OPERATION_DENIED.
#[test]
fn the_user_picks_the_account() {
    let mut authenticator = authenticator();
    let first = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::DeviceOnly),
    );
    let second = register(
        &mut authenticator,
        RP_ID,
        b"user-2",
        true,
        Some(Origin::SeedRecoverable),
    );
    register(&mut authenticator, "other.example", b"user-3", true, None);
    let (response, asked) = assert_with(
        &mut authenticator,
        &assertion(None, &[]),
        Answer::Confirmed,
        1,
    );
    assert_eq!(response[0], OK);
    let picked = asserted(&response[1..]);
    assert!(picked.signed_by(&first), "the second listed, the older one");
    assert_eq!(picked.user_selected, Some(true));
    assert_eq!(picked.number_of_credentials, None);
    let shown = |origin| Shown {
        name: Some(String::from("alice")),
        display_name: Some(String::from("Alice")),
        origin: Some(origin),
    };
    assert_eq!(
        asked,
        [(
            Asked::Pick {
                rp_id: String::from(RP_ID),
                accounts: vec![shown(Origin::SeedRecoverable), shown(Origin::DeviceOnly)],
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
    let (response, _) = assert_with(
        &mut authenticator,
        &assertion(None, &[]),
        Answer::Confirmed,
        0,
    );
    assert!(asserted(&response[1..]).signed_by(&second));
    let (response, _) = assert_with(
        &mut authenticator,
        &assertion(None, &[]),
        Answer::Rejected,
        0,
    );
    assert_eq!(response, [OPERATION_DENIED]);
}

/// Without presence or verification asked for, several discoverable credentials are not listed:
/// the first answers with `numberOfCredentials`, no UP and no screen, and authenticatorGetNextAssertion
/// returns the others in order, newest first; past the last it is CTAP2_ERR_NOT_ALLOWED (§6.2.2
/// step 15.2.2, §6.3).
#[test]
fn get_next_assertion_returns_the_rest() {
    let mut authenticator = authenticator();
    let made: Vec<_> = [b"user-1", b"user-2", b"user-3"]
        .iter()
        .map(|user| register(&mut authenticator, RP_ID, *user, true, None))
        .collect();
    let (response, asked) = assert_with(
        &mut authenticator,
        &assertion(None, &[("up", false)]),
        Answer::Rejected,
        0,
    );
    assert_eq!(response[0], OK);
    assert_eq!(asked, [], "no screen");
    let first = asserted(&response[1..]);
    assert_eq!(first.number_of_credentials, Some(3));
    assert_eq!(first.flags(), 0, "device-only, no UP, no UV");
    assert!(first.signed_by(&made[2]));
    for expected in [&made[1], &made[0]] {
        let (response, _) = assert_with(&mut authenticator, &[0x08], Answer::Rejected, 0);
        assert_eq!(response[0], OK);
        let next = asserted(&response[1..]);
        assert!(next.signed_by(expected));
        assert_eq!(next.number_of_credentials, None);
        assert_eq!(next.user_selected, None);
    }
    let (response, _) = assert_with(&mut authenticator, &[0x08], Answer::Rejected, 0);
    assert_eq!(response, [NOT_ALLOWED]);
}

/// authenticatorGetNextAssertion continues only the command right before it, within 30 seconds
/// of the last call (§6.3 steps 1 and 3): without an assertion, after another command, or late,
/// it is CTAP2_ERR_NOT_ALLOWED.
#[test]
fn get_next_assertion_needs_its_assertion() {
    let mut authenticator = authenticator();
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    let (response, _) = assert_with(&mut authenticator, &[0x08], Answer::Confirmed, 0);
    assert_eq!(response, [NOT_ALLOWED], "no assertion");

    let start = assertion(None, &[("up", false)]);
    assert_with(&mut authenticator, &start, Answer::Confirmed, 0);
    assert_with(&mut authenticator, &[0x04], Answer::Confirmed, 0);
    let (response, _) = assert_with(&mut authenticator, &[0x08], Answer::Confirmed, 0);
    assert_eq!(response, [NOT_ALLOWED], "after another command");

    let mut ui = Scripted::new(Answer::Confirmed);
    assert_eq!(run(&mut authenticator, &mut ui, &start)[0], OK);
    ui.now_ms = NEXT_ASSERTION_TIMEOUT_MS + 1;
    assert_eq!(
        run(&mut authenticator, &mut ui, &[0x08]),
        [NOT_ALLOWED],
        "late"
    );
}

/// A first assertion whose response does not fit the caller's buffer leaves nothing for
/// authenticatorGetNextAssertion to continue: §6.3 continues an assertion the platform received,
/// so the next call is CTAP2_ERR_NOT_ALLOWED rather than a signature for the second credential.
#[test]
fn a_failed_assertion_leaves_no_continuation() {
    let mut authenticator = authenticator();
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut short = [0u8; 16];
    authenticator.process(
        &assertion(None, &[("up", false)]),
        Link::Usb,
        &mut ui,
        &mut short,
    );
    assert_ne!(short[0], OK, "the response cannot fit 16 bytes");
    assert_eq!(run(&mut authenticator, &mut ui, &[0x08]), [NOT_ALLOWED]);
}

/// An assertion authenticated by a pinUvAuthToken leaves its continuation only while that token
/// lives: once the token's max usage time period ends, authenticatorGetNextAssertion is
/// CTAP2_ERR_NOT_ALLOWED although its own 30 seconds have not passed (§6 "stateful commands":
/// the state MUST be discarded when the token that authenticated the initializing command
/// expires). A token-authenticated assertion continues over the NFC tap, where no account list
/// is shown.
#[test]
fn a_continuation_ends_with_its_token() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, session) = uv_token(&mut authenticator, &mut ui, Some(0x02), Some(RP_ID));
    assert_eq!(response[0], OK);
    let token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));
    let request = |up: bool| {
        command(
            0x02,
            &[
                (0x01, Value::Text(RP_ID)),
                (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (0x05, options(&[("up", up)])),
                (
                    0x06,
                    Value::Bytes(hmac(&token, &[&CLIENT_DATA_HASH]).to_vec()),
                ),
                (0x07, Value::Uint(2)),
            ],
        )
    };
    // A first use within the initial usage time limit keeps the token for its full period; one
    // without presence leaves its permissions for the next.
    ui.now_ms = 1;
    assert_eq!(run(&mut authenticator, &mut ui, &request(false))[0], OK);
    ui.now_ms = MAX_USAGE_TIME_PERIOD_MS - 1_000;
    authenticator.nfc_tap(NfcTap {
        at_ms: ui.now_ms,
        selection: 0,
    });
    let mut response = [0u8; 1024];
    let length = authenticator.process(&request(true), Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    assert_eq!(
        asserted(&response[1..length]).number_of_credentials,
        Some(2)
    );
    ui.now_ms = MAX_USAGE_TIME_PERIOD_MS + 1_000;
    assert_eq!(run(&mut authenticator, &mut ui, &[0x08]), [NOT_ALLOWED]);
}

/// An assertion that fails after the tap gave its presence, here for a response that does not
/// fit, still uses the tap up, and the next sign-in asks on the screen.
#[test]
fn a_failed_assertion_uses_the_tap() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = assertion(Some(&[&made.id]), &[]);
    let mut short = [0u8; 16];
    authenticator.process(&request, Link::Nfc, &mut ui, &mut short);
    assert_ne!(short[0], OK, "the response cannot fit 16 bytes");
    assert_eq!(ui.asked, [], "no screen on the tap");
    let mut response = [0u8; 1024];
    authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(ui.asked.len(), 1, "the tap was used");
}

/// Over a live NFC tap an assertion without presence but with user verification lists no
/// accounts either: the device rests on the phone, so the platform gets the count and goes on
/// with getNextAssertion. UP stays clear, as no presence was asked for, and the tap is not used.
#[test]
fn a_tap_lists_no_accounts_for_an_assertion_without_presence() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 1024];
    let length = authenticator.process(
        &assertion(None, &[("up", false), ("uv", true)]),
        Link::Nfc,
        &mut ui,
        &mut response,
    );
    assert_eq!(response[0], OK);
    let first = asserted(&response[1..length]);
    assert_eq!(first.number_of_credentials, Some(2));
    assert_eq!(first.flags(), UV, "UV, no UP");
    assert_eq!(ui.asked, [], "no screen on the tap");
    let length = authenticator.process(&assertion(None, &[]), Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    assert_eq!(ui.asked, [], "the tap is still unused");
    assert_eq!(asserted(&response[1..length]).flags(), UP);
}

/// Another command ends the continuation even when its caller gives no room for a response:
/// §6.3 continues only the command right before it, whatever became of the one in between.
#[test]
fn a_command_without_room_still_ends_the_continuation() {
    let mut authenticator = authenticator();
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    let mut ui = Scripted::new(Answer::Confirmed);
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &assertion(None, &[("up", false)])
        )[0],
        OK
    );
    authenticator.process(&[0x04], Link::Usb, &mut ui, &mut []);
    assert_eq!(run(&mut authenticator, &mut ui, &[0x08]), [NOT_ALLOWED]);
}

/// An empty allowList denotes no credential: §6.2 lets an authenticator use only the credentials
/// a present allowList denotes, and the discoverable credentials of §6.2.2 are searched only when
/// it is absent. A discoverable credential of the RP therefore does not sign, and no screen is
/// shown for it.
#[test]
fn an_empty_allow_list_finds_no_credentials() {
    let mut authenticator = authenticator();
    register(&mut authenticator, RP_ID, b"user-1", true, None);
    let (response, asked) = assert_with(
        &mut authenticator,
        &assertion(Some(&[]), &[]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response, [NO_CREDENTIALS]);
    assert_eq!(asked, [], "no screen");
}

/// Nothing to sign with is CTAP2_ERR_NO_CREDENTIALS: an RP without credentials, an allowList of
/// IDs this device did not create or created for another RP. A platform never sends `rk`, which
/// is CTAP2_ERR_UNSUPPORTED_OPTION (§6.2.2 step 5.4).
#[test]
fn no_credentials_and_unsupported_options() {
    let mut authenticator = authenticator();
    let other = register(&mut authenticator, "other.example", b"user-1", false, None);
    for request in [
        assertion(None, &[]),
        assertion(Some(&[&[1, 2, 3], &other.id]), &[]),
    ] {
        let (response, asked) = assert_with(&mut authenticator, &request, Answer::Confirmed, 0);
        assert_eq!(response, [NO_CREDENTIALS]);
        assert_eq!(asked, [], "no screen");
    }
    let (response, _) = assert_with(
        &mut authenticator,
        &assertion(None, &[("rk", true)]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response, [UNSUPPORTED_OPTION]);
}

/// A discoverable credential that a registration for the same RP and user replaced no longer
/// signs, even when its ID carries everything a seed-recoverable key needs (§6.1.3); the
/// replacement does. A device-only key of the replaced one is gone with its slot.
#[test]
fn a_replaced_credential_no_longer_signs() {
    for origin in [Origin::SeedRecoverable, Origin::DeviceOnly] {
        let mut authenticator = authenticator();
        let old = register(&mut authenticator, RP_ID, b"user-1", true, Some(origin));
        let new = register(&mut authenticator, RP_ID, b"user-1", true, Some(origin));
        let (response, _) = assert_with(
            &mut authenticator,
            &assertion(Some(&[&old.id]), &[]),
            Answer::Confirmed,
            0,
        );
        assert_eq!(response, [NO_CREDENTIALS], "{origin:?}");
        let (response, _) = assert_with(
            &mut authenticator,
            &assertion(Some(&[&new.id]), &[]),
            Answer::Confirmed,
            0,
        );
        assert!(asserted(&response[1..]).signed_by(&new), "{origin:?}");
    }
}

/// Removes the index entry holding `id`, as deleteCredential does.
fn remove_entry(authenticator: &mut Authenticator<SoftCrypto, MemoryStorage>, id: &[u8]) {
    let entry = authenticator
        .store
        .entries()
        .find(|entry| entry.credential_id == id)
        .map(|entry| entry.id)
        .expect("the credential is in the index");
    assert!(authenticator.store.remove(entry));
}

/// A deleted discoverable credential no longer signs, also from an allowList with its ID (CTAP
/// 2.2 §6.1.3), whatever its origin; a seed-recoverable ID would otherwise open from the
/// recovery phrase alone.
#[test]
fn a_deleted_credential_no_longer_signs() {
    for origin in [Origin::SeedRecoverable, Origin::DeviceOnly] {
        let mut authenticator = authenticator();
        let made = register(&mut authenticator, RP_ID, b"user-1", true, Some(origin));
        remove_entry(&mut authenticator, &made.id);
        let (response, asked) = assert_with(
            &mut authenticator,
            &assertion(Some(&[&made.id]), &[]),
            Answer::Confirmed,
            0,
        );
        assert_eq!(response, [NO_CREDENTIALS], "{origin:?}");
        assert_eq!(asked, [], "no screen for {origin:?}");
    }
}

/// A credential replaced by a newer one for the same user stays revoked once the newer one is
/// deleted too: neither ID signs (§6.1.3). Without the store binding the older seed-recoverable
/// ID came back, as no entry of the user was left to tell it was replaced.
#[test]
fn a_replaced_credential_stays_revoked_after_its_replacement_is_deleted() {
    let mut authenticator = authenticator();
    let old = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::SeedRecoverable),
    );
    let new = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::SeedRecoverable),
    );
    remove_entry(&mut authenticator, &new.id);
    for id in [&old.id, &new.id] {
        let (response, _) = assert_with(
            &mut authenticator,
            &assertion(Some(&[id]), &[]),
            Answer::Confirmed,
            0,
        );
        assert_eq!(response, [NO_CREDENTIALS]);
    }
}

/// On NVM installed fresh with the same recovery phrase, a seed-recoverable credential, also a
/// discoverable one, signs again from its ID alone; a device-only one does not, its key gone with
/// the NVM.
#[test]
fn the_recovery_phrase_brings_seed_credentials_back() {
    let mut authenticator = authenticator();
    let seed = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::SeedRecoverable),
    );
    let device = register(
        &mut authenticator,
        RP_ID,
        b"user-2",
        false,
        Some(Origin::DeviceOnly),
    );
    let mut reinstalled = Authenticator::new(
        super::super::tests::settings(Transports::Usb),
        SoftCrypto::new([0x11; KEY_LEN], [0x33; KEY_LEN]),
        Store::open(MemoryStorage::new(4, 4)),
    );
    let (response, _) = assert_with(
        &mut reinstalled,
        &assertion(Some(&[&seed.id]), &[]),
        Answer::Confirmed,
        0,
    );
    assert!(asserted(&response[1..]).signed_by(&seed));
    let (response, _) = assert_with(
        &mut reinstalled,
        &assertion(Some(&[&device.id]), &[]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response, [NO_CREDENTIALS]);
}

/// authenticatorReset revokes every credential (CTAP 2.2 §6.6): after it no earlier ID signs.
#[test]
fn reset_revokes_credentials() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let (response, _) = assert_with(&mut authenticator, &[0x07], Answer::Confirmed, 0);
    assert_eq!(response, [OK]);
    let (response, _) = assert_with(
        &mut authenticator,
        &assertion(Some(&[&made.id]), &[]),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response, [NO_CREDENTIALS]);
}

/// A pinUvAuthParam from a token with the ga permission sets UV (§6.2.2 step 7.1); the
/// ceremony then clears the token's permissions (step 11.4), so the same token is
/// CTAP2_ERR_PIN_AUTH_INVALID the second time.
#[test]
fn a_token_with_ga_verifies_the_user() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, session) = uv_token(&mut authenticator, &mut ui, Some(0x02), Some(RP_ID));
    assert_eq!(response[0], OK);
    let token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));
    let mut members = vec![
        (0x01, Value::Text(RP_ID)),
        (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
        (0x03, descriptors(&[&made.id])),
        (
            0x06,
            Value::Bytes(hmac(&token, &[&CLIENT_DATA_HASH]).to_vec()),
        ),
        (0x07, Value::Uint(2)),
    ];
    let request = command(0x02, &members);
    let response = run(&mut authenticator, &mut ui, &request);
    assert_eq!(response[0], OK);
    assert_eq!(asserted(&response[1..]).flags(), UP | UV | BE | BS);
    assert_eq!(
        run(&mut authenticator, &mut ui, &request),
        [PIN_AUTH_INVALID]
    );
    members[3].1 = Value::Bytes(vec![0; 32]);
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x02, &members)),
        [PIN_AUTH_INVALID]
    );
}

/// Counts the heap the thread that measures holds, and its peak; other threads pass through.
struct Counting;

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static HELD: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn count(change: isize) {
    if MEASURING.try_with(Cell::get).unwrap_or(false) {
        let held = HELD.get() + change;
        HELD.set(held);
        PEAK.set(PEAK.get().max(held));
    }
}

fn size(layout: Layout) -> isize {
    isize::try_from(layout.size()).expect("an allocation is at most isize::MAX bytes")
}

// SAFETY: every call goes to the system allocator with the caller's arguments; counting touches
// only thread-local cells, which never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            count(size(layout));
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed on.
        unsafe { System.dealloc(pointer, layout) };
        count(-size(layout));
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The most heap `run` held at once, beyond what was held before it.
fn peak_heap(run: impl FnOnce()) -> isize {
    HELD.set(0);
    PEAK.set(0);
    MEASURING.set(true);
    run();
    MEASURING.set(false);
    PEAK.get()
}

/// A user who reads every account the picker offers and takes the first.
struct Reader;

impl Ui for Reader {
    fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
        Answer::Confirmed
    }

    fn register(&mut self, _registration: Registration<'_>, _timeout_ms: u32) -> Choice<Origin> {
        Choice::Rejected
    }

    fn pick<A: Accounts>(
        &mut self,
        _rp_id: &str,
        accounts: &mut A,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        for index in 0..accounts.count() {
            let name = accounts.read(index, |account| account.name == Some("alice"));
            assert_eq!(name, Some(true));
        }
        Choice::Chose(0)
    }

    fn browse<P: Passkeys>(
        &mut self,
        _passkeys: &mut P,
        _start: usize,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        Choice::Rejected
    }

    fn device_unlocked(&mut self) -> bool {
        true
    }

    fn now_ms(&self) -> u64 {
        0
    }
}

/// The heap a sign-in with `credentials` discoverable credentials for the RP holds at its peak,
/// the user picking an account.
fn sign_in_heap(credentials: usize) -> isize {
    let mut authenticator = Authenticator::new(
        super::super::tests::settings(Transports::Usb),
        SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]),
        Store::open(MemoryStorage::new(credentials, 4)),
    );
    for user in 0..credentials {
        let user_id = format!("user-{user}");
        register(
            &mut authenticator,
            RP_ID,
            user_id.as_bytes(),
            true,
            Some(Origin::SeedRecoverable),
        );
    }
    let request = assertion(None, &[]);
    let mut response = [0u8; 1024];
    let mut status = None;
    let peak = peak_heap(|| {
        authenticator.process(&request, Link::Usb, &mut Reader, &mut response);
        status = Some(response[0]);
    });
    assert_eq!(status, Some(OK));
    peak
}

/// A sign-in to an RP that holds every index slot fits the device's small heap: the credentials
/// are read one at a time, for the picker and for the signature, so each one adds only its place
/// in the index lists to the peak, not its decoded credential and names.
#[test]
fn a_sign_in_holds_one_credential_at_a_time() {
    let few = sign_in_heap(2);
    let many = sign_in_heap(64);
    let per_credential = (many - few) / 62;
    assert!(
        per_credential <= 96,
        "{per_credential} bytes per credential ({few} for 2, {many} for 64)"
    );
}

/// Over NFC the tap is the presence of one assertion: no screen, UP set, and with several
/// discoverable credentials the count for getNextAssertion instead of a list nobody can answer
/// while the device lies on the phone. The next assertion on the same tap asks on the screen.
#[test]
fn a_tap_asserts_without_a_screen_once() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    for user in [b"user-1", b"user-2"] {
        register(&mut authenticator, RP_ID, user, true, None);
    }
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 1024];
    let length = authenticator.process(&assertion(None, &[]), Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    let first = asserted(&response[1..length]);
    assert_eq!(first.flags(), UP);
    assert_eq!(first.number_of_credentials, Some(2));
    assert_eq!(ui.asked, []);
    authenticator.process(&assertion(None, &[]), Link::Nfc, &mut ui, &mut response);
    assert!(
        matches!(&ui.asked[..], [(Asked::Pick { .. }, _)]),
        "the tap was used: {:?}",
        ui.asked
    );
}

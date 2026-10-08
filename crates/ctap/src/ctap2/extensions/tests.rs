//! credProtect, hmac-secret and hmac-secret-mc against CTAP 2.2 §12.1, §12.7 and §12.8, end to
//! end through the authenticator. The platform half (key agreement, salt encryption and MAC,
//! output decryption) and the HMAC of the outputs are computed with the RustCrypto crates, apart
//! from the code under test.

use super::super::client_pin::tests::{Session, Value, command, encoded, hmac, run};
use super::super::get_assertion::tests::{Asserted, asserted};
use super::super::make_credential::tests::{
    CLIENT_DATA_HASH, ED, Made, OK, RP_ID, descriptors, made, options, register, registration,
};
use super::super::tests::{Scripted, TestAuthenticator, authenticator, authenticator_with};
use super::super::{Link, NfcTap, Transports};
use crate::cbor::{Decoder, Key, validate};
use crate::credential_id::{self, KeySource, Origin};
use crate::keys::KeyRing;
use crate::pin::Protocol;
use crate::ui::Answer;
use sha2::Sha256;

const INVALID_PARAMETER: u8 = 0x02;
const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const MISSING_PARAMETER: u8 = 0x14;
const UNSUPPORTED_OPTION: u8 = 0x2B;
const NO_CREDENTIALS: u8 = 0x2E;
const PIN_AUTH_INVALID: u8 = 0x33;

const SALT1: [u8; 32] = [0xA1; 32];
const SALT2: [u8; 32] = [0xB2; 32];

/// The extension outputs of an authenticator data, by name, with the order the keys came in.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outputs {
    names: Vec<String>,
    cred_protect: Option<u64>,
    /// makeCredential's `"hmac-secret": true`.
    created: Option<bool>,
    /// getAssertion's encrypted hmac-secret output.
    secret: Option<Vec<u8>>,
    /// The encrypted hmac-secret-mc output.
    secret_mc: Option<Vec<u8>>,
}

/// Reads an extensions map: `hmac-secret` is a boolean after a registration and a byte string
/// after an assertion.
fn outputs(bytes: &[u8], registration: bool) -> Outputs {
    assert_eq!(validate(bytes), Ok(()), "canonical CBOR");
    let mut decoder = Decoder::new(bytes);
    let outputs = decoder
        .map(|entries| {
            let mut outputs = Outputs::default();
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                let Key::Text(name) = key else {
                    panic!("an extension name");
                };
                outputs.names.push(String::from(name));
                match name {
                    "credProtect" => outputs.cred_protect = Some(value.unsigned()?),
                    "hmac-secret" if registration => outputs.created = Some(value.bool()?),
                    "hmac-secret" => outputs.secret = Some(value.bytes()?.to_vec()),
                    "hmac-secret-mc" => outputs.secret_mc = Some(value.bytes()?.to_vec()),
                    _ => panic!("unexpected extension output {name}"),
                }
            }
            Ok(outputs)
        })
        .expect("an extensions map");
    decoder.finish().expect("one item");
    outputs
}

/// An extensions map of `(name, encoded value)` pairs, given in canonical order.
fn extensions(members: &[(&str, Vec<u8>)]) -> Value {
    let mut map = encoded(|encoder| {
        encoder.map(members.len()).expect("room");
    });
    for (name, value) in members {
        map.extend(encoded(|encoder| {
            encoder.text(name).expect("room");
        }));
        map.extend_from_slice(value);
    }
    Value::Raw(map)
}

fn cbor_true() -> Vec<u8> {
    encoded(|encoder| {
        encoder.bool(true).expect("room");
    })
}

fn cbor_uint(value: u64) -> Vec<u8> {
    encoded(|encoder| {
        encoder.unsigned(value).expect("room");
    })
}

/// The hmac-secret input {1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: protocol} for `salts`,
/// with the protocol member only when `protocol` is given.
fn hmac_input(session: &Session, salts: &[u8], protocol: Option<u64>) -> Vec<u8> {
    let salt_enc = session.encrypt(salts);
    let salt_auth = session.authenticate(&[&salt_enc]);
    hmac_input_raw(session, &salt_enc, &salt_auth, protocol)
}

fn hmac_input_raw(
    session: &Session,
    salt_enc: &[u8],
    salt_auth: &[u8],
    protocol: Option<u64>,
) -> Vec<u8> {
    let mut input = encoded(|encoder| {
        encoder
            .map(3 + usize::from(protocol.is_some()))
            .and_then(|encoder| encoder.unsigned(0x01))
            .expect("room");
    });
    input.extend_from_slice(session.cose_key());
    input.extend(encoded(|encoder| {
        encoder
            .unsigned(0x02)
            .and_then(|encoder| encoder.bytes(salt_enc))
            .and_then(|encoder| encoder.unsigned(0x03))
            .and_then(|encoder| encoder.bytes(salt_auth))
            .expect("room");
        if let Some(protocol) = protocol {
            encoder
                .unsigned(0x04)
                .and_then(|encoder| encoder.unsigned(protocol))
                .expect("room");
        }
    }));
    input
}

/// A registration of `user_id` with built-in UV and these extensions, for a user who confirms
/// with `origin`; returns the status and, on success, the response.
fn register_with(
    authenticator: &mut TestAuthenticator,
    user_id: &[u8],
    rk: bool,
    origin: Option<Origin>,
    members: &[(&str, Vec<u8>)],
) -> (u8, Option<Made>) {
    let mut request = registration(RP_ID, user_id, &[("rk", rk), ("uv", true)]);
    // Canonical order: extensions (6) before options (7).
    request.insert(4, (0x06, extensions(members)));
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.origin = origin;
    let response = run(authenticator, &mut ui, &command(0x01, &request));
    let made = (response[0] == OK).then(|| made(&response[1..]));
    (response[0], made)
}

/// An assertion of `RP_ID` with `allow_list`, options `opts` and these extensions; returns the
/// status and, on success, the response.
fn assert_with(
    authenticator: &mut TestAuthenticator,
    allow_list: Option<&[&[u8]]>,
    members: &[(&str, Vec<u8>)],
    opts: &[(&str, bool)],
) -> (u8, Option<Asserted>) {
    let mut request = vec![
        (0x01, Value::Text(RP_ID)),
        (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
    ];
    if let Some(ids) = allow_list {
        request.push((0x03, descriptors(ids)));
    }
    if !members.is_empty() {
        request.push((0x04, extensions(members)));
    }
    request.push((0x05, options(opts)));
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(authenticator, &mut ui, &command(0x02, &request));
    let asserted = (response[0] == OK).then(|| asserted(&response[1..]));
    (response[0], asserted)
}

/// The hmac-secret output of an assertion of `made` with `salts`, with or without UV, decrypted.
fn secret(
    authenticator: &mut TestAuthenticator,
    made: &Made,
    salts: &[u8],
    uv: bool,
    protocol: Protocol,
) -> Vec<u8> {
    let session = Session::start(authenticator, protocol);
    let input = hmac_input(&session, salts, Some(protocol as u64));
    let (status, asserted) = assert_with(
        authenticator,
        Some(&[&made.id]),
        &[("hmac-secret", input)],
        &[("uv", uv)],
    );
    assert_eq!(status, OK);
    let asserted = asserted.expect("an assertion");
    assert_eq!(asserted.flags() & ED, ED);
    let output = outputs(asserted.extensions(), false);
    assert_eq!(output.names, ["hmac-secret"]);
    session.decrypt(&output.secret.expect("an hmac-secret output"))
}

/// HKDF-SHA-256 (RFC 5869) with a 32-byte output, from the RustCrypto crate.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes");
    out
}

/// The CredRandom of `made` with or without UV, computed here from what its origin keeps, apart
/// from the derivation under test: the slot of a discoverable device-only credential, or the key
/// model's HKDF chain below the device key or below the root key of the application node 11..11
/// (`HKDF(K, info = "cred-random")`, then `salt = cs`, `info = "uv" | "no-uv"`).
fn cred_random(authenticator: &mut TestAuthenticator, made: &Made, uv: bool) -> [u8; 32] {
    // Opening the ID only recovers the credential seed the derivation starts from.
    let keys = KeyRing::new(&mut authenticator.crypto);
    let reset_id = authenticator.store.config().reset_id;
    let credential = credential_id::open(&authenticator.crypto, &keys, RP_ID, &made.id, reset_id)
        .expect("the credential opens");
    let info: &[u8] = if uv { b"uv" } else { b"no-uv" };
    let derive = |root: &[u8], cs: &[u8; 32]| {
        let k_hmac = hkdf_sha256(&[0; 32], root, b"cred-random");
        hkdf_sha256(cs, &k_hmac, info)
    };
    match credential.key {
        KeySource::Seed(cs) => {
            let k_root = hkdf_sha256(b"structured-passkeys/v1", &[0x11; 32], b"root");
            derive(&k_root, &cs)
        }
        KeySource::Device(cs) => {
            let k_dev = authenticator.store.device_key().expect("a device key");
            derive(&k_dev[..], &cs)
        }
        KeySource::Slot { index, tag } => {
            let secrets = authenticator.store.key(index, &tag).expect("a live slot");
            if uv {
                *secrets.cred_random_uv
            } else {
                *secrets.cred_random
            }
        }
    }
}

/// The outputs of an encoded map follow canonical order, `credProtect` and `hmac-secret` of equal
/// length bytewise, then `hmac-secret-mc` (CTAP 2.2 §8 canonical CBOR); none is written for
/// extensions the request did not carry.
#[test]
fn outputs_are_written_in_canonical_order() {
    let all = super::Outputs {
        cred_protect: Some(crate::credential_id::CredProtect::Required),
        hmac_secret: Some(super::HmacSecretOutput::Created),
        hmac_secret_mc: Some(vec![0x55; 32]),
    };
    let bytes = all.encode().expect("fits");
    let read = outputs(&bytes, true);
    assert_eq!(read.names, ["credProtect", "hmac-secret", "hmac-secret-mc"]);
    assert_eq!(read.cred_protect, Some(3));
    assert_eq!(read.created, Some(true));
    assert_eq!(read.secret_mc, Some(vec![0x55; 32]));
    assert!(super::Outputs::default().is_empty());
}

/// A registration without extensions has no ED flag and no outputs (§12.1: no unsolicited
/// credProtect output), and its credential is level 1.
#[test]
fn a_registration_without_extensions_has_no_outputs() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    assert_eq!(made.flags & ED, 0);
    assert!(made.extensions.is_empty());
}

/// credProtect is kept with the credential and answered with the level set (§12.1). Level 3 is
/// never used without user verification, even with its ID in the allowList; with UV it signs.
#[test]
fn cred_protect_three_needs_user_verification() {
    let mut authenticator = authenticator();
    let (status, made) = register_with(
        &mut authenticator,
        b"user-1",
        false,
        None,
        &[("credProtect", cbor_uint(3))],
    );
    assert_eq!(status, OK);
    let made = made.expect("a registration");
    assert_eq!(made.flags & ED, ED);
    let read = outputs(&made.extensions, true);
    assert_eq!(read.names, ["credProtect"]);
    assert_eq!(read.cred_protect, Some(3));
    let (status, _) = assert_with(&mut authenticator, Some(&[&made.id]), &[], &[]);
    assert_eq!(status, NO_CREDENTIALS);
    let (status, asserted) =
        assert_with(&mut authenticator, Some(&[&made.id]), &[], &[("uv", true)]);
    assert_eq!(status, OK);
    assert!(asserted.expect("an assertion").signed_by(&made));
}

/// Level 2 keeps a discoverable credential out of an assertion without UV and without an
/// allowList, and lets it sign when the allowList names it (§12.1,
/// userVerificationOptionalWithCredentialIDList).
#[test]
fn cred_protect_two_needs_the_id_or_user_verification() {
    let mut authenticator = authenticator();
    let (status, made) = register_with(
        &mut authenticator,
        b"user-1",
        true,
        Some(Origin::SeedRecoverable),
        &[("credProtect", cbor_uint(2))],
    );
    assert_eq!(status, OK);
    let made = made.expect("a registration");
    assert_eq!(outputs(&made.extensions, true).cred_protect, Some(2));
    let (status, _) = assert_with(&mut authenticator, None, &[], &[]);
    assert_eq!(status, NO_CREDENTIALS);
    let (status, _) = assert_with(&mut authenticator, None, &[], &[("uv", true)]);
    assert_eq!(status, OK);
    let (status, _) = assert_with(&mut authenticator, Some(&[&made.id]), &[], &[]);
    assert_eq!(status, OK);
}

/// A credProtect value outside 1..3 is refused as OpenSK refuses it,
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE, before any screen; a value of another type too.
#[test]
fn an_undefined_cred_protect_is_refused() {
    let mut authenticator = authenticator();
    for value in [cbor_uint(0), cbor_uint(4), cbor_true()] {
        let (status, _) = register_with(
            &mut authenticator,
            b"user-1",
            false,
            None,
            &[("credProtect", value)],
        );
        assert_eq!(status, CBOR_UNEXPECTED_TYPE);
    }
}

/// `"hmac-secret": true` at registration is answered `true` (§12.7): every credential has its
/// CredRandom values.
#[test]
fn hmac_secret_at_registration_answers_true() {
    let mut authenticator = authenticator();
    let (status, made) = register_with(
        &mut authenticator,
        b"user-1",
        false,
        None,
        &[("hmac-secret", cbor_true())],
    );
    assert_eq!(status, OK);
    let read = outputs(&made.expect("a registration").extensions, true);
    assert_eq!(read.names, ["hmac-secret"]);
    assert_eq!(read.created, Some(true));
}

/// hmac-secret-mc without `"hmac-secret": true` is CTAP2_ERR_MISSING_PARAMETER (§12.8), and an
/// input without saltAuth too.
#[test]
fn hmac_secret_mc_needs_hmac_secret_and_its_members() {
    let mut authenticator = authenticator();
    let session = Session::start(&mut authenticator, Protocol::Two);
    let input = hmac_input(&session, &SALT1, Some(2));
    let (status, _) = register_with(
        &mut authenticator,
        b"user-1",
        false,
        None,
        &[("hmac-secret-mc", input)],
    );
    assert_eq!(status, MISSING_PARAMETER);
    let mut incomplete = encoded(|encoder| {
        encoder
            .map(2)
            .and_then(|encoder| encoder.unsigned(0x01))
            .expect("room");
    });
    incomplete.extend_from_slice(session.cose_key());
    incomplete.extend(encoded(|encoder| {
        encoder
            .unsigned(0x02)
            .and_then(|encoder| encoder.bytes(&session.encrypt(&SALT1)))
            .expect("room");
    }));
    let (status, _) = register_with(
        &mut authenticator,
        b"user-1",
        false,
        None,
        &[("hmac-secret", cbor_true()), ("hmac-secret-mc", incomplete)],
    );
    assert_eq!(status, MISSING_PARAMETER);
}

/// The PRF at registration and at sign-in agree: for each key origin and both PIN/UV protocols,
/// the hmac-secret-mc output is HMAC-SHA-256(CredRandomWithUV, salt) for each salt (§12.8,
/// §12.7), the same output an assertion with UV returns later, and an assertion without UV
/// returns HMAC under CredRandomWithoutUV, a different one. Two assertions agree.
#[test]
fn the_prf_is_stable_per_credential_and_differs_without_uv() {
    let cases = [
        (true, Origin::DeviceOnly),
        (true, Origin::SeedRecoverable),
        (false, Origin::DeviceOnly),
        (false, Origin::SeedRecoverable),
    ];
    for protocol in [Protocol::One, Protocol::Two] {
        for (rk, origin) in cases {
            let mut authenticator = authenticator();
            let session = Session::start(&mut authenticator, protocol);
            let mut salts = SALT1.to_vec();
            salts.extend_from_slice(&SALT2);
            let input = hmac_input(&session, &salts, Some(protocol as u64));
            let (status, made) = register_with(
                &mut authenticator,
                b"user-1",
                rk,
                Some(origin),
                &[("hmac-secret", cbor_true()), ("hmac-secret-mc", input)],
            );
            assert_eq!(status, OK, "{protocol:?} rk {rk} {origin:?}");
            let made = made.expect("a registration");
            let read = outputs(&made.extensions, true);
            assert_eq!(read.names, ["hmac-secret", "hmac-secret-mc"]);
            assert_eq!(read.created, Some(true));
            let at_registration = session.decrypt(&read.secret_mc.expect("an mc output"));
            let with_uv = cred_random(&mut authenticator, &made, true);
            let without_uv = cred_random(&mut authenticator, &made, false);
            assert_ne!(with_uv, without_uv);
            let mut expected = hmac(&with_uv, &[&SALT1]).to_vec();
            expected.extend_from_slice(&hmac(&with_uv, &[&SALT2]));
            assert_eq!(at_registration, expected, "{protocol:?} rk {rk} {origin:?}");

            let signed_with_uv = secret(&mut authenticator, &made, &salts, true, protocol);
            assert_eq!(signed_with_uv, at_registration);
            let signed_without_uv = secret(&mut authenticator, &made, &salts, false, protocol);
            let mut expected = hmac(&without_uv, &[&SALT1]).to_vec();
            expected.extend_from_slice(&hmac(&without_uv, &[&SALT2]));
            assert_eq!(signed_without_uv, expected);
            assert_ne!(signed_without_uv, signed_with_uv);
            assert_eq!(
                secret(&mut authenticator, &made, &salts, false, protocol),
                signed_without_uv
            );
        }
    }
}

/// One salt gives one output, and different credentials different outputs for the same salt.
#[test]
fn one_salt_gives_one_output_per_credential() {
    let mut authenticator = authenticator();
    let first = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let second = register(&mut authenticator, RP_ID, b"user-2", false, None);
    let a = secret(&mut authenticator, &first, &SALT1, true, Protocol::Two);
    let b = secret(&mut authenticator, &second, &SALT1, true, Protocol::Two);
    assert_eq!(a.len(), 32);
    assert_eq!(
        a,
        hmac(&cred_random(&mut authenticator, &first, true), &[&SALT1])
    );
    assert_ne!(a, b);
}

/// Without pinUvAuthProtocol the input is protocol 1 (§12.7, "let the value of pinUvAuthProtocol
/// be 1"): salts a protocol-one session encrypted give the output it decrypts.
#[test]
fn an_input_without_protocol_is_protocol_one() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let session = Session::start(&mut authenticator, Protocol::One);
    let input = hmac_input(&session, &SALT1, None);
    let (status, asserted) = assert_with(
        &mut authenticator,
        Some(&[&made.id]),
        &[("hmac-secret", input)],
        &[],
    );
    assert_eq!(status, OK);
    let output = outputs(asserted.expect("an assertion").extensions(), false);
    let plain = session.decrypt(&output.secret.expect("an output"));
    assert_eq!(
        plain,
        hmac(&cred_random(&mut authenticator, &made, false), &[&SALT1])
    );
}

/// hmac-secret needs user presence: `up` false is CTAP2_ERR_UNSUPPORTED_OPTION (§12.7).
#[test]
fn hmac_secret_without_presence_is_refused() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let session = Session::start(&mut authenticator, Protocol::Two);
    let input = hmac_input(&session, &SALT1, Some(2));
    let (status, _) = assert_with(
        &mut authenticator,
        Some(&[&made.id]),
        &[("hmac-secret", input)],
        &[("up", false)],
    );
    assert_eq!(status, UNSUPPORTED_OPTION);
}

/// The salts are checked as §12.7 orders: a saltAuth that does not verify is
/// CTAP2_ERR_PIN_AUTH_INVALID; salts that decrypt to other than 32 or 64 bytes, or that do not
/// decrypt, CTAP1_ERR_INVALID_PARAMETER; so is a protocol the authenticator does not support.
#[test]
fn bad_salts_are_refused() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let session = Session::start(&mut authenticator, Protocol::Two);
    let salt_enc = session.encrypt(&SALT1);
    let wrong_mac = hmac_input_raw(&session, &salt_enc, &[0; 32], Some(2));
    let short = hmac_input(&session, &[0xC3; 48], Some(2));
    let long = hmac_input(&session, &[0xC3; 80], Some(2));
    let partial = {
        let salt_enc = &salt_enc[..40];
        hmac_input_raw(
            &session,
            salt_enc,
            &session.authenticate(&[salt_enc]),
            Some(2),
        )
    };
    let unsupported = hmac_input(&session, &SALT1, Some(3));
    for (input, status) in [
        (wrong_mac, PIN_AUTH_INVALID),
        (short, INVALID_PARAMETER),
        (long, INVALID_PARAMETER),
        (partial, INVALID_PARAMETER),
        (unsupported, INVALID_PARAMETER),
    ] {
        let (got, _) = assert_with(
            &mut authenticator,
            Some(&[&made.id]),
            &[("hmac-secret", input)],
            &[],
        );
        assert_eq!(got, status);
    }
}

/// A registration whose hmac-secret-mc salts fail creates nothing: no discoverable credential is
/// stored and no key slot is taken.
#[test]
fn failed_registration_salts_store_nothing() {
    let mut authenticator = authenticator();
    let session = Session::start(&mut authenticator, Protocol::Two);
    let salt_enc = session.encrypt(&SALT1);
    let wrong_mac = hmac_input_raw(&session, &salt_enc, &[0; 32], Some(2));
    let (status, _) = register_with(
        &mut authenticator,
        b"user-1",
        true,
        Some(Origin::DeviceOnly),
        &[("hmac-secret", cbor_true()), ("hmac-secret-mc", wrong_mac)],
    );
    assert_eq!(status, PIN_AUTH_INVALID);
    assert_eq!(authenticator.store.entries().count(), 0);
    let (status, _) = assert_with(&mut authenticator, None, &[], &[("uv", true)]);
    assert_eq!(status, NO_CREDENTIALS);
}

/// getNextAssertion answers the hmac-secret salts of the assertion it continues, each under its
/// own credential's CredRandom (§6.3 returns the next credential of the same assertion). Over the
/// NFC tap no account list is shown, so the platform gets the count and the rest one by one.
#[test]
fn next_assertions_answer_the_same_salts() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let first = register(&mut authenticator, RP_ID, b"user-1", true, None);
    let second = register(&mut authenticator, RP_ID, b"user-2", true, None);
    let session = Session::start(&mut authenticator, Protocol::Two);
    let input = hmac_input(&session, &SALT1, Some(2));
    let request = command(
        0x02,
        &[
            (0x01, Value::Text(RP_ID)),
            (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (0x04, extensions(&[("hmac-secret", input)])),
        ],
    );
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 1024];
    let length = authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    let one = asserted(&response[1..length]);
    assert_eq!(one.number_of_credentials, Some(2));
    let next = run(&mut authenticator, &mut ui, &[0x08]);
    assert_eq!(next[0], OK);
    let two = asserted(&next[1..]);
    for (asserted, made) in [(&one, &second), (&two, &first)] {
        assert_eq!(asserted.id, made.id, "most recent first");
        let output = outputs(asserted.extensions(), false);
        assert_eq!(
            session.decrypt(&output.secret.expect("an output")),
            hmac(&cred_random(&mut authenticator, made, false), &[&SALT1])
        );
    }
}

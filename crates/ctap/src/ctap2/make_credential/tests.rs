//! authenticatorMakeCredential against CTAP 2.2 §6.1.2, end to end through the authenticator.
//! Authenticator data is read and attestation signatures are checked here with the RustCrypto
//! crates, apart from the code under test.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::super::client_pin::tests::{Value, command, encoded, run, set_pin, uv_token};
use super::super::tests::{
    Asked, Scripted, Shown, TestAuthenticator, authenticator, authenticator_with,
};
use super::super::{AAGUID, Link, NfcTap, Transports};
use crate::cbor::{Decoder, Key};
use crate::credential_id::Origin;
use crate::pin::Protocol;
use crate::ui::{Answer, MAX_SHOWN_LEN, USER_ACTION_TIMEOUT_MS};

pub(in crate::ctap2) const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
const MISSING_PARAMETER: u8 = 0x14;
const CREDENTIAL_EXCLUDED: u8 = 0x19;
const UNSUPPORTED_ALGORITHM: u8 = 0x26;
const OPERATION_DENIED: u8 = 0x27;
const KEY_STORE_FULL: u8 = 0x28;
const INVALID_OPTION: u8 = 0x2C;
const KEEPALIVE_CANCEL: u8 = 0x2D;
const PIN_INVALID: u8 = 0x31;
const PIN_AUTH_INVALID: u8 = 0x33;
const PIN_NOT_SET: u8 = 0x35;
const PUAT_REQUIRED: u8 = 0x36;

/// Authenticator data flags (WebAuthn L3 §6.1): UP, UV, BE, BS, AT.
pub(in crate::ctap2) const UP: u8 = 0x01;
pub(in crate::ctap2) const UV: u8 = 0x04;
pub(in crate::ctap2) const BE: u8 = 0x08;
pub(in crate::ctap2) const BS: u8 = 0x10;
const AT: u8 = 0x40;

pub(in crate::ctap2) const RP_ID: &str = "example.com";
pub(in crate::ctap2) const CLIENT_DATA_HASH: [u8; 32] = [0xCD; 32];

/// The `rp` member {"id": rp_id}.
fn rp(rp_id: &str) -> Value {
    Value::Raw(encoded(|encoder| {
        encoder
            .map(1)
            .and_then(|encoder| encoder.text("id"))
            .and_then(|encoder| encoder.text(rp_id))
            .expect("room");
    }))
}

/// The `user` member {"id", "name", "displayName"} in canonical order.
fn user(id: &[u8], name: &str, display_name: &str) -> Value {
    Value::Raw(encoded(|encoder| {
        encoder
            .map(3)
            .and_then(|encoder| encoder.text("id"))
            .and_then(|encoder| encoder.bytes(id))
            .and_then(|encoder| encoder.text("name"))
            .and_then(|encoder| encoder.text(name))
            .and_then(|encoder| encoder.text("displayName"))
            .and_then(|encoder| encoder.text(display_name))
            .expect("room");
    }))
}

/// pubKeyCredParams with these algorithms, each {"alg": alg, "type": "public-key"}.
fn params(algorithms: &[i64]) -> Value {
    Value::Raw(encoded(|encoder| {
        encoder.array(algorithms.len()).expect("room");
        for &alg in algorithms {
            encoder
                .map(2)
                .and_then(|encoder| encoder.text("alg"))
                .and_then(|encoder| encoder.int(alg))
                .and_then(|encoder| encoder.text("type"))
                .and_then(|encoder| encoder.text("public-key"))
                .expect("room");
        }
    }))
}

/// An array of descriptors {"id": id, "type": "public-key"}.
pub(in crate::ctap2) fn descriptors(ids: &[&[u8]]) -> Value {
    Value::Raw(encoded(|encoder| {
        encoder.array(ids.len()).expect("room");
        for id in ids {
            encoder
                .map(2)
                .and_then(|encoder| encoder.text("id"))
                .and_then(|encoder| encoder.bytes(id))
                .and_then(|encoder| encoder.text("type"))
                .and_then(|encoder| encoder.text("public-key"))
                .expect("room");
        }
    }))
}

/// An options map of `(key, value)` pairs, given in canonical order.
pub(in crate::ctap2) fn options(pairs: &[(&str, bool)]) -> Value {
    Value::Raw(encoded(|encoder| {
        encoder.map(pairs.len()).expect("room");
        for (key, value) in pairs {
            encoder
                .text(key)
                .and_then(|encoder| encoder.bool(*value))
                .expect("room");
        }
    }))
}

/// A registration of `user_id` ("alice" / "Alice") at `rp_id` with ES256 and `opts`.
fn registration(rp_id: &str, user_id: &[u8], opts: &[(&str, bool)]) -> Vec<(u64, Value)> {
    vec![
        (0x01, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
        (0x02, rp(rp_id)),
        (0x03, user(user_id, "alice", "Alice")),
        (0x04, params(&[-7])),
        (0x07, options(opts)),
    ]
}

/// What a makeCredential response holds.
#[derive(Debug)]
pub(in crate::ctap2) struct Made {
    pub(in crate::ctap2) fmt: String,
    pub(in crate::ctap2) auth_data: Vec<u8>,
    pub(in crate::ctap2) flags: u8,
    pub(in crate::ctap2) id: Vec<u8>,
    /// The credential public key, uncompressed SEC1.
    pub(in crate::ctap2) public_key: Vec<u8>,
    /// attStmt `alg` and `sig`, if any.
    pub(in crate::ctap2) statement: Option<(i64, Vec<u8>)>,
}

/// Reads the response body of a makeCredential, and the attested credential data of its
/// authenticator data (WebAuthn L3 §6.5.1) by its byte layout.
pub(in crate::ctap2) fn made(body: &[u8]) -> Made {
    let mut decoder = Decoder::new(body);
    let (fmt, auth_data, statement) = decoder
        .map(|entries| {
            let mut fmt = String::new();
            let mut auth_data = Vec::new();
            let mut statement = None;
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => fmt = String::from(value.text()?),
                    Key::Int(2) => auth_data = value.bytes()?.to_vec(),
                    Key::Int(3) => {
                        statement = value.map(|members| {
                            let mut alg = None;
                            let mut sig = None;
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("alg") => alg = Some(member.int()?),
                                    Key::Text("sig") => sig = Some(member.bytes()?.to_vec()),
                                    _ => member.skip()?,
                                }
                            }
                            Ok(alg.zip(sig))
                        })?;
                    }
                    _ => value.skip()?,
                }
            }
            Ok((fmt, auth_data, statement))
        })
        .expect("a response map");
    decoder.finish().expect("one item");
    assert_eq!(auth_data[33..37], [0, 0, 0, 0], "signature counter 0");
    assert_eq!(auth_data[37..53], AAGUID, "AAGUID");
    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let id = auth_data[55..55 + id_len].to_vec();
    // COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}: x after the 10-byte head, y 3 bytes later.
    let key = &auth_data[55 + id_len..];
    assert_eq!(
        key[..10],
        [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20],
        "COSE_Key head"
    );
    let mut public_key = vec![0x04];
    public_key.extend_from_slice(&key[10..42]);
    assert_eq!(key[42..45], [0x22, 0x58, 0x20], "COSE_Key y head");
    public_key.extend_from_slice(&key[45..77]);
    assert_eq!(key.len(), 77, "nothing after the key");
    Made {
        fmt,
        flags: auth_data[32],
        auth_data,
        id,
        public_key,
        statement,
    }
}

/// Whether `signature` (DER) is the credential key's ES256 signature of `message`.
pub(in crate::ctap2) fn verifies(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = VerifyingKey::from_sec1_bytes(public_key).expect("a P-256 point");
    let signature = DerSignature::try_from(signature).expect("a DER signature");
    key.verify(message, &signature).is_ok()
}

/// Registers `user_id` at `rp_id` with built-in UV for a user who confirms with `origin` (the
/// default when `None`); returns the response.
pub(in crate::ctap2) fn register(
    authenticator: &mut TestAuthenticator,
    rp_id: &str,
    user_id: &[u8],
    rk: bool,
    origin: Option<Origin>,
) -> Made {
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.origin = origin;
    let response = run(
        authenticator,
        &mut ui,
        &command(
            0x01,
            &registration(rp_id, user_id, &[("rk", rk), ("uv", true)]),
        ),
    );
    assert_eq!(response[0], OK, "registration of {user_id:02x?}");
    made(&response[1..])
}

/// A registration with built-in UV (the `uv` option, the device unlock) answers with packed self
/// attestation (WebAuthn L3 §8.2): authenticator data with the SHA-256 of the RP ID, UP, UV and
/// AT, a counter of 0 and the AAGUID, and a statement {"alg": -7, "sig"} that the new credential's
/// key signed over the authenticator data and clientDataHash. A non-discoverable credential is
/// seed-recoverable by default, so BE and BS are set. The screen names the RP and the user and
/// offers that origin first.
#[test]
fn registers_with_packed_self_attestation() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        &mut authenticator,
        &mut ui,
        &command(
            0x01,
            &registration(RP_ID, b"user-1", &[("rk", false), ("uv", true)]),
        ),
    );
    assert_eq!(response[0], OK);
    let made = made(&response[1..]);
    assert_eq!(made.fmt, "packed");
    assert_eq!(made.auth_data[..32], Sha256::digest(RP_ID)[..]);
    assert_eq!(made.flags, UP | UV | AT | BE | BS);
    let (alg, sig) = made.statement.expect("attStmt");
    assert_eq!(alg, -7);
    let mut signed = made.auth_data.clone();
    signed.extend_from_slice(&CLIENT_DATA_HASH);
    assert!(
        verifies(&made.public_key, &signed, &sig),
        "self attestation"
    );
    assert_eq!(
        ui.asked,
        [(
            Asked::Registration {
                rp_id: String::from(RP_ID),
                account: Shown {
                    name: Some(String::from("alice")),
                    display_name: Some(String::from("Alice")),
                    origin: None,
                },
                default_origin: Origin::SeedRecoverable,
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
}

/// The origin selector starts on device-only for a discoverable credential with user
/// verification, seed-recoverable otherwise; the user's choice decides, and the backup flags
/// follow it: BE and BS for a seed-recoverable key, neither for a device-only one.
#[test]
fn the_user_chooses_the_key_origin() {
    for (rk, chosen, default_origin) in [
        (false, None, Origin::SeedRecoverable),
        (true, None, Origin::DeviceOnly),
        (false, Some(Origin::DeviceOnly), Origin::SeedRecoverable),
        (true, Some(Origin::SeedRecoverable), Origin::DeviceOnly),
    ] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(Answer::Confirmed);
        ui.origin = chosen;
        let response = run(
            &mut authenticator,
            &mut ui,
            &command(
                0x01,
                &registration(RP_ID, b"user-1", &[("rk", rk), ("uv", true)]),
            ),
        );
        assert_eq!(response[0], OK, "{rk} {chosen:?}");
        let flags = made(&response[1..]).flags;
        let origin = chosen.unwrap_or(default_origin);
        let backup = if origin == Origin::SeedRecoverable {
            BE | BS
        } else {
            0
        };
        assert_eq!(flags, UP | UV | AT | backup, "{rk} {chosen:?}");
        assert!(
            matches!(
                &ui.asked[..],
                [(Asked::Registration { default_origin: shown, .. }, _)] if *shown == default_origin
            ),
            "{rk} {chosen:?}: {:?}",
            ui.asked
        );
    }
}

/// A refusal or no answer on the registration screen is CTAP2_ERR_OPERATION_DENIED, a cancel
/// CTAP2_ERR_KEEPALIVE_CANCEL (§6.1.2 step 18.1.2, §11.2.9.1.5); nothing is stored.
#[test]
fn a_refused_registration_stores_nothing() {
    for (answer, status) in [
        (Answer::Rejected, OPERATION_DENIED),
        (Answer::TimedOut, OPERATION_DENIED),
        (Answer::Cancelled, KEEPALIVE_CANCEL),
    ] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(answer);
        let response = run(
            &mut authenticator,
            &mut ui,
            &command(
                0x01,
                &registration(RP_ID, b"user-1", &[("rk", true), ("uv", true)]),
            ),
        );
        assert_eq!(response, [status], "{answer:?}");
        assert_eq!(authenticator.store().entries().count(), 0, "{answer:?}");
        assert_eq!(authenticator.store().remaining_keys(), 3, "{answer:?}");
    }
}

/// makeCredUvNotRqd is false (§6.1.2 step 10): a request with neither the uv option nor a
/// pinUvAuthParam is refused before any screen, CTAP2_ERR_PUAT_REQUIRED once a client PIN is set
/// and CTAP2_ERR_OPERATION_DENIED without one.
#[test]
fn a_credential_needs_user_verification() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = command(0x01, &registration(RP_ID, b"user-1", &[("rk", false)]));
    assert_eq!(
        run(&mut authenticator, &mut ui, &request),
        [OPERATION_DENIED]
    );
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    assert_eq!(run(&mut authenticator, &mut ui, &request), [PUAT_REQUIRED]);
    assert_eq!(ui.asked, [], "no screen");
}

/// §6.1.2 step 5.6: `up` false is CTAP2_ERR_INVALID_OPTION.
#[test]
fn up_false_is_an_invalid_option() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = command(
        0x01,
        &registration(RP_ID, b"user-1", &[("up", false), ("uv", true)]),
    );
    assert_eq!(run(&mut authenticator, &mut ui, &request), [INVALID_OPTION]);
}

/// §6.1.2 step 3: without ES256 in pubKeyCredParams the answer is
/// CTAP2_ERR_UNSUPPORTED_ALGORITHM; ES256 after an unsupported one is chosen. An element without
/// `alg` is a missing parameter.
#[test]
fn pub_key_cred_params_choose_es256() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut members = registration(RP_ID, b"user-1", &[("uv", true)]);
    members[3].1 = params(&[-8]);
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x01, &members)),
        [UNSUPPORTED_ALGORITHM]
    );
    members[3].1 = params(&[-8, -7]);
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x01, &members))[0],
        OK
    );
    members[3].1 = Value::Raw(encoded(|encoder| {
        encoder
            .array(1)
            .and_then(|encoder| encoder.map(1))
            .and_then(|encoder| encoder.text("type"))
            .and_then(|encoder| encoder.text("public-key"))
            .expect("room");
    }));
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x01, &members)),
        [MISSING_PARAMETER]
    );
}

/// clientDataHash, rp, user and pubKeyCredParams are required: without one the answer is
/// CTAP2_ERR_MISSING_PARAMETER.
#[test]
fn required_members_are_missing_parameters() {
    for skipped in 0..4 {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(Answer::Confirmed);
        let mut members = registration(RP_ID, b"user-1", &[("uv", true)]);
        members.remove(skipped);
        assert_eq!(
            run(&mut authenticator, &mut ui, &command(0x01, &members)),
            [MISSING_PARAMETER],
            "without member {}",
            skipped + 1
        );
    }
}

/// §6.1.2 step 9: this authenticator has no enterprise attestation, so a request for it is
/// CTAP1_ERR_INVALID_PARAMETER. A discoverable credential stores a user handle of at most 64
/// bytes (WebAuthn L3 §5.4.3); a longer one is refused before any screen.
#[test]
fn invalid_parameters_ask_nothing() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut members = registration(RP_ID, b"user-1", &[("uv", true)]);
    members.push((0x0A, Value::Uint(1)));
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x01, &members)),
        [INVALID_PARAMETER]
    );
    let request = command(
        0x01,
        &registration(RP_ID, &[0x55; 65], &[("rk", true), ("uv", true)]),
    );
    assert_eq!(
        run(&mut authenticator, &mut ui, &request),
        [INVALID_PARAMETER]
    );
    assert_eq!(ui.asked, []);
}

/// An empty user handle is a valid account identifier (CTAP 2.2 §6.1, user: "while an empty
/// account identifier is valid, it has known interoperability hurdles in practice"): a
/// discoverable credential is created with it and an assertion returns it.
#[test]
fn an_empty_user_handle_is_valid() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"", true, None);
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = command(
        0x02,
        &[
            (0x01, Value::Text(RP_ID)),
            (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
        ],
    );
    let response = run(&mut authenticator, &mut ui, &request);
    assert_eq!(response[0], OK);
    let mut decoder = Decoder::new(&response[1..]);
    let (id, user_id) = decoder
        .map(|entries| {
            let mut id = Vec::new();
            let mut user_id = None;
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => {
                        id = value.map(|members| {
                            let mut id = Vec::new();
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                if key == Key::Text("id") {
                                    id = member.bytes()?.to_vec();
                                } else {
                                    member.skip()?;
                                }
                            }
                            Ok(id)
                        })?;
                    }
                    Key::Int(4) => {
                        user_id = Some(value.map(|members| {
                            let mut user_id = None;
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                if key == Key::Text("id") {
                                    user_id = Some(member.bytes()?.to_vec());
                                } else {
                                    member.skip()?;
                                }
                            }
                            Ok(user_id)
                        })?);
                    }
                    _ => value.skip()?,
                }
            }
            Ok((id, user_id))
        })
        .expect("a response map");
    assert_eq!(id, made.id);
    assert_eq!(
        user_id,
        Some(Some(Vec::new())),
        "the empty handle comes back"
    );
}

/// A registration with a pinUvAuthParam (§6.1.2 step 11.1): a token with the mc permission for
/// this RP, obtained with built-in UV, gives UV. A MAC that does not verify, a token without mc
/// or bound to another RP is CTAP2_ERR_PIN_AUTH_INVALID. The ceremony then clears the token's
/// cached presence, verification and permissions (step 18.4), so the same token does not create
/// a second credential.
#[test]
fn a_token_with_mc_verifies_the_user() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, session) = uv_token(&mut authenticator, &mut ui, Some(0x01), Some(RP_ID));
    assert_eq!(response[0], OK);
    let token = session.decrypt(
        &super::super::client_pin::tests::parse_response(&response[1..])
            .token
            .expect("token"),
    );
    let param = super::super::client_pin::tests::hmac(&token, &[&CLIENT_DATA_HASH]).to_vec();
    let with_param = |param: Vec<u8>| {
        let mut members = registration(RP_ID, b"user-1", &[("rk", true)]);
        members.push((0x08, Value::Bytes(param)));
        members.push((0x09, Value::Uint(2)));
        command(0x01, &members)
    };
    assert_eq!(
        run(&mut authenticator, &mut ui, &with_param(vec![0; 32])),
        [PIN_AUTH_INVALID]
    );
    ui.asked.clear();
    let response = run(&mut authenticator, &mut ui, &with_param(param.clone()));
    assert_eq!(response[0], OK);
    assert_eq!(made(&response[1..]).flags & (UP | UV), UP | UV);
    assert_eq!(ui.asked.len(), 1, "the registration screen still shows");
    assert_eq!(
        run(&mut authenticator, &mut ui, &with_param(param)),
        [PIN_AUTH_INVALID],
        "the token's permissions were used up"
    );

    // A token for another RP, or with only ga.
    for (permissions, rp_id) in [(0x01, "other.example"), (0x02, RP_ID)] {
        let (response, session) =
            uv_token(&mut authenticator, &mut ui, Some(permissions), Some(rp_id));
        assert_eq!(response[0], OK);
        let token = session.decrypt(
            &super::super::client_pin::tests::parse_response(&response[1..])
                .token
                .expect("token"),
        );
        let param = super::super::client_pin::tests::hmac(&token, &[&CLIENT_DATA_HASH]).to_vec();
        assert_eq!(
            run(&mut authenticator, &mut ui, &with_param(param)),
            [PIN_AUTH_INVALID],
            "{permissions:#x} {rp_id}"
        );
    }
}

/// §6.1.2 step 1: a zero-length pinUvAuthParam asks for evidence of user interaction, then
/// answers CTAP2_ERR_PIN_NOT_SET or CTAP2_ERR_PIN_INVALID by the PIN state; a refusal is
/// CTAP2_ERR_OPERATION_DENIED. Step 2: a pinUvAuthParam without its protocol is
/// CTAP2_ERR_MISSING_PARAMETER, with an unsupported one CTAP1_ERR_INVALID_PARAMETER.
#[test]
fn pin_uv_auth_param_probes_and_protocols() {
    let mut authenticator = authenticator();
    let probe = |members_extra: Vec<(u64, Value)>| {
        let mut members = registration(RP_ID, b"user-1", &[]);
        members.extend(members_extra);
        command(0x01, &members)
    };
    let mut ui = Scripted::new(Answer::Confirmed);
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &probe(vec![(0x08, Value::Bytes(vec![])), (0x09, Value::Uint(2))])
        ),
        [PIN_NOT_SET]
    );
    assert_eq!(ui.asked, [(Asked::Selection, USER_ACTION_TIMEOUT_MS)]);
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &probe(vec![(0x08, Value::Bytes(vec![])), (0x09, Value::Uint(2))])
        ),
        [PIN_INVALID]
    );
    let mut refusing = Scripted::new(Answer::Rejected);
    assert_eq!(
        run(
            &mut authenticator,
            &mut refusing,
            &probe(vec![(0x08, Value::Bytes(vec![])), (0x09, Value::Uint(2))])
        ),
        [OPERATION_DENIED]
    );
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &probe(vec![(0x08, Value::Bytes(vec![0; 32]))])
        ),
        [MISSING_PARAMETER]
    );
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &probe(vec![
                (0x08, Value::Bytes(vec![0; 32])),
                (0x09, Value::Uint(3))
            ])
        ),
        [INVALID_PARAMETER]
    );
}

/// §6.1.2 step 16: a credential of the excludeList created here for this RP is reported only
/// after user presence on the device, CTAP2_ERR_CREDENTIAL_EXCLUDED whatever the answer, a
/// cancel aside; an ID of another RP or that this device did not create is passed over.
#[test]
fn the_exclude_list_needs_presence() {
    let mut authenticator = authenticator();
    let first = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let other = register(&mut authenticator, "other.example", b"user-1", false, None);
    for (answer, status) in [
        (Answer::Confirmed, CREDENTIAL_EXCLUDED),
        (Answer::Rejected, CREDENTIAL_EXCLUDED),
        (Answer::TimedOut, CREDENTIAL_EXCLUDED),
        (Answer::Cancelled, KEEPALIVE_CANCEL),
    ] {
        let mut ui = Scripted::new(answer);
        let mut members = registration(RP_ID, b"user-2", &[("uv", true)]);
        members.insert(4, (0x05, descriptors(&[&[1, 2, 3], &other.id, &first.id])));
        assert_eq!(
            run(&mut authenticator, &mut ui, &command(0x01, &members)),
            [status],
            "{answer:?}"
        );
        assert_eq!(
            ui.asked,
            [(
                Asked::Excluded {
                    rp_id: String::from(RP_ID)
                },
                USER_ACTION_TIMEOUT_MS
            )],
            "{answer:?}"
        );
    }
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut members = registration(RP_ID, b"user-2", &[("uv", true)]);
    members.insert(4, (0x05, descriptors(&[&other.id])));
    assert_eq!(
        run(&mut authenticator, &mut ui, &command(0x01, &members))[0],
        OK,
        "another RP's credential excludes nothing"
    );
}

/// A replacement whose response does not fit the caller's buffer stores nothing: the credential
/// it would replace keeps its index entry and its device-only key and still signs, since the
/// relying party never received the new one.
#[test]
fn a_failed_response_keeps_the_replaced_credential() {
    let mut authenticator = authenticator();
    let old = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::DeviceOnly),
    );
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.origin = Some(Origin::DeviceOnly);
    let request = command(
        0x01,
        &registration(RP_ID, b"user-1", &[("rk", true), ("uv", true)]),
    );
    let mut short = [0u8; 16];
    authenticator.process(&request, Link::Usb, &mut ui, &mut short);
    assert_ne!(short[0], OK, "the response cannot fit 16 bytes");
    let entries: Vec<_> = authenticator
        .store()
        .entries()
        .map(|entry| entry.credential_id.to_vec())
        .collect();
    assert_eq!(
        entries,
        core::slice::from_ref(&old.id),
        "the old entry stays"
    );
    let assertion = command(
        0x02,
        &[
            (0x01, Value::Text(RP_ID)),
            (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (0x03, descriptors(&[&old.id])),
        ],
    );
    assert_eq!(
        run(&mut authenticator, &mut ui, &assertion)[0],
        OK,
        "the old credential still signs"
    );
}

/// §6.1.2 step 22: a discoverable credential for the RP and user of an existing one replaces
/// it, in the same index slot; a full index is CTAP2_ERR_KEY_STORE_FULL, and a device-only
/// discoverable credential also needs a free key slot beyond the one kept for replacements.
#[test]
fn discoverable_credentials_replace_and_fill_the_index() {
    let mut authenticator = authenticator();
    for user in [b"user-1", b"user-1", b"user-2", b"user-3"] {
        register(
            &mut authenticator,
            RP_ID,
            user,
            true,
            Some(Origin::DeviceOnly),
        );
    }
    assert_eq!(
        authenticator.store().entries().count(),
        3,
        "user-1 replaced"
    );
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.origin = Some(Origin::DeviceOnly);
    let request = command(
        0x01,
        &registration(RP_ID, b"user-4", &[("rk", true), ("uv", true)]),
    );
    assert_eq!(
        run(&mut authenticator, &mut ui, &request),
        [KEY_STORE_FULL],
        "no key slot left"
    );
    ui.origin = Some(Origin::SeedRecoverable);
    assert_eq!(
        run(&mut authenticator, &mut ui, &request)[0],
        OK,
        "a seed-recoverable one needs no key slot"
    );
    let request = command(
        0x01,
        &registration(RP_ID, b"user-5", &[("rk", true), ("uv", true)]),
    );
    assert_eq!(
        run(&mut authenticator, &mut ui, &request),
        [KEY_STORE_FULL],
        "no index slot left"
    );
}

/// Over NFC the tap is the presence for one credential operation: a registration within two
/// minutes of it shows no screen and takes the default origin; the next one, on the same tap,
/// asks on the screen.
#[test]
fn a_tap_registers_without_a_screen_once() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let mut ui = Scripted::new(Answer::Confirmed);
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let request = command(
        0x01,
        &registration(RP_ID, b"user-1", &[("rk", true), ("uv", true)]),
    );
    let mut response = [0u8; 1024];
    let length = authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    assert_eq!(
        made(&response[1..length]).flags,
        UP | UV | AT,
        "device-only by default"
    );
    assert_eq!(ui.asked, [], "no screen on the tap");
    authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(ui.asked.len(), 1, "the tap was used");
}

/// A registration the excludeList ends takes its presence from the tap, which then counts as
/// used: the tap is the presence of one credential operation, and the next one asks on the
/// screen.
#[test]
fn an_excluded_registration_uses_the_tap() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let existing = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let mut ui = Scripted::new(Answer::Confirmed);
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    let mut members = registration(RP_ID, b"user-2", &[("uv", true)]);
    members.insert(4, (0x05, descriptors(&[&existing.id])));
    let mut response = [0u8; 1024];
    authenticator.process(&command(0x01, &members), Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], CREDENTIAL_EXCLUDED);
    assert_eq!(ui.asked, [], "the tap is the presence");
    let request = command(0x01, &registration(RP_ID, b"user-2", &[("uv", true)]));
    authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(ui.asked.len(), 1, "the tap was used");
}

/// A new selection of the applet is a new tap even within the same tick of the 100 ms device
/// clock: after NFCCTAP_CONTROL ends CTAP and the platform selects the applet again, the next
/// registration takes the new tap without a screen.
#[test]
fn a_new_selection_is_a_new_tap_within_one_tick() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = command(
        0x01,
        &registration(RP_ID, b"user-1", &[("rk", true), ("uv", true)]),
    );
    let mut response = [0u8; 1024];
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 0,
    });
    authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    authenticator.nfc_ended();
    authenticator.nfc_tap(NfcTap {
        at_ms: 0,
        selection: 1,
    });
    authenticator.process(&request, Link::Nfc, &mut ui, &mut response);
    assert_eq!(response[0], OK);
    assert_eq!(ui.asked, [], "each selection was a tap");
}

/// attestationFormatsPreference picks the supported format with the lowest index (CTAP 2.2
/// §6.1.2: "MUST choose a supported format whose attestation statement format identifier appears
/// with the lowest index"); "none" leaves the attestation out with an empty statement, and a list
/// naming no supported format keeps the default, packed.
#[test]
fn attestation_follows_the_preference_order() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    for (preference, expected) in [
        (&["none"][..], "none"),
        (&["none", "packed"][..], "none"),
        (&["tpm", "none", "packed"][..], "none"),
        (&["packed", "none"][..], "packed"),
        (&["tpm"][..], "packed"),
        (&[][..], "packed"),
    ] {
        let mut members = registration(RP_ID, b"user-1", &[("uv", true)]);
        members.push((
            0x0B,
            Value::Raw(encoded(|encoder| {
                let mut encoder = encoder.array(preference.len()).expect("room");
                for format in preference {
                    encoder = encoder.text(format).expect("room");
                }
            })),
        ));
        let response = run(&mut authenticator, &mut ui, &command(0x01, &members));
        assert_eq!(response[0], OK, "{preference:?}");
        let made = made(&response[1..]);
        assert_eq!(made.fmt, expected, "{preference:?}");
        assert_eq!(
            made.statement.is_none(),
            expected == "none",
            "{preference:?}"
        );
    }
}

/// Names from the relying party are shown cut to the 64 bytes a credential keeps, in the printable
/// ASCII the device fonts hold: any other character, `<` included, is written as `<` its code
/// point in hex `>`. Different names therefore never look alike: "Иван" and "Петр" differ, a name
/// typed as `<418>` differs from the letter И, and a line break does not push the rest off the
/// screen.
#[test]
fn names_are_shown_safely() {
    let shown = |name: &str, display_name: &str| {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(Answer::Confirmed);
        let mut members = registration(RP_ID, b"user-1", &[("uv", true)]);
        members[2].1 = user(b"user-1", name, display_name);
        assert_eq!(
            run(&mut authenticator, &mut ui, &command(0x01, &members))[0],
            OK
        );
        let [(Asked::Registration { account, .. }, _)] = &ui.asked[..] else {
            panic!("a registration screen: {:?}", ui.asked);
        };
        (account.name.clone(), account.display_name.clone())
    };
    let long = "é".repeat(40);
    assert_eq!(
        shown("ali\nce", &long),
        (Some("ali<A>ce".into()), Some("<E9>".repeat(32)))
    );
    assert_eq!(
        shown("Иван", "<418>"),
        (Some("<418><432><430><43D>".into()), Some("<3C>418>".into()))
    );
    assert_eq!(shown("Петр", "x").0, Some("<41F><435><442><440>".into()));
    // The longest shown name, every kept byte at four characters, is MAX_SHOWN_LEN, so a screen
    // with that much room tells names apart in their last byte too.
    let (a, b) = (
        format!("{}a", "<".repeat(63)),
        format!("{}b", "<".repeat(63)),
    );
    let (shown_a, shown_b) = (shown(&a, "x").0.unwrap(), shown(&b, "x").0.unwrap());
    assert_ne!(shown_a, shown_b);
    assert_eq!(shown_a.len(), 63 * 4 + 1);
    let longest = shown(&"<".repeat(64), &"\u{7F}".repeat(64));
    assert_eq!(longest.0.map(|name| name.len()), Some(MAX_SHOWN_LEN));
    assert_eq!(longest.1.map(|name| name.len()), Some(MAX_SHOWN_LEN));
}

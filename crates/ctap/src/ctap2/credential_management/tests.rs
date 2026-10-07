//! authenticatorCredentialManagement against CTAP 2.2 §6.8, end to end through the authenticator:
//! registrations with makeCredential, a token from built-in user verification, then the
//! subcommands and what getAssertion sees afterwards.

use sha2::{Digest, Sha256};

use super::super::client_pin::tests::{
    Value, command, encoded, hmac, parse_response, run, uv_token,
};
use super::super::make_credential::tests::{
    CLIENT_DATA_HASH, Made, OK, RP_ID, descriptors, options, register,
};
use super::super::tests::{Asked, Scripted, Shown, TestAuthenticator, settings};
use super::super::{Authenticator, NEXT_ASSERTION_TIMEOUT_MS, Transports};
use crate::cbor::{Decoder, Key};
use crate::credential_id::Origin;
use crate::crypto::KEY_LEN;
use crate::soft::SoftCrypto;
use crate::storage::{MemoryStorage, Store};
use crate::ui::{Answer, USER_ACTION_TIMEOUT_MS};

const INVALID_PARAMETER: u8 = 0x02;
const MISSING_PARAMETER: u8 = 0x14;
const OPERATION_DENIED: u8 = 0x27;
const KEY_STORE_FULL: u8 = 0x28;
const NO_CREDENTIALS: u8 = 0x2E;
const USER_ACTION_TIMEOUT: u8 = 0x2F;
const NOT_ALLOWED: u8 = 0x30;
const PIN_AUTH_INVALID: u8 = 0x33;
const PUAT_REQUIRED: u8 = 0x36;
const INVALID_SUBCOMMAND: u8 = 0x3E;

/// The `cm` permission bit (§6.5.5.7).
const CM: u64 = 0x04;
/// The `ga` permission bit.
const GA: u64 = 0x02;

/// An authenticator on fresh NVM with room for `slots` discoverable credentials and
/// `name_slots` name overrides.
fn authenticator_with_room(slots: usize, name_slots: usize) -> TestAuthenticator {
    Authenticator::new(
        settings(Transports::Usb),
        SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]),
        Store::open(MemoryStorage::with_name_slots(slots, slots + 1, name_slots)),
    )
}

/// A pinUvAuthToken from built-in user verification with `permissions` and permissions RP ID
/// `rp_id`, decrypted.
fn token(
    authenticator: &mut TestAuthenticator,
    permissions: u64,
    rp_id: Option<&'static str>,
) -> Vec<u8> {
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, session) = uv_token(authenticator, &mut ui, Some(permissions), rp_id);
    assert_eq!(response[0], OK, "a token");
    session.decrypt(&parse_response(&response[1..]).token.expect("a token"))
}

/// A subCommandParams map with the members given in canonical key order, encoded.
fn sub_params(members: &[(u64, Value)]) -> Vec<u8> {
    let mut params = encoded(|encoder| {
        encoder.map(members.len()).expect("room");
    });
    for (key, value) in members {
        params.extend(encoded(|encoder| {
            encoder.unsigned(*key).expect("room");
        }));
        match value {
            Value::Raw(raw) => params.extend_from_slice(raw),
            Value::Bytes(bytes) => params.extend(encoded(|encoder| {
                encoder.bytes(bytes).expect("room");
            })),
            Value::Uint(value) => params.extend(encoded(|encoder| {
                encoder.unsigned(*value).expect("room");
            })),
            Value::Text(text) => params.extend(encoded(|encoder| {
                encoder.text(text).expect("room");
            })),
        }
    }
    params
}

/// A credential management request for `sub_command` with `params`, its pinUvAuthParam the
/// protocol two MAC under `token` over the subcommand and the parameters (§6.8).
fn request(sub_command: u8, params: Option<&[u8]>, token: &[u8]) -> Vec<u8> {
    let param = hmac(token, &[&[sub_command], params.unwrap_or_default()]);
    let mut members = vec![(0x01, Value::Uint(u64::from(sub_command)))];
    if let Some(params) = params {
        members.push((0x02, Value::Raw(params.to_vec())));
    }
    members.push((0x03, Value::Uint(2)));
    members.push((0x04, Value::Bytes(param.to_vec())));
    command(0x0A, &members)
}

/// A continuation, which carries only its subcommand.
fn next(sub_command: u8) -> Vec<u8> {
    command(0x0A, &[(0x01, Value::Uint(u64::from(sub_command)))])
}

/// rpIDHash for `rp_id`.
fn rp_hash_params(rp_id: &str) -> Vec<u8> {
    sub_params(&[(0x01, Value::Bytes(Sha256::digest(rp_id).to_vec()))])
}

/// credentialID for `id`, plus `user` when given.
fn credential_params(id: &[u8], user: Option<Value>) -> Vec<u8> {
    let mut members = vec![(0x02, descriptors(&[id]))];
    // descriptors writes an array; the member is one descriptor.
    if let (_, Value::Raw(array)) = &members[0] {
        let descriptor = array[1..].to_vec();
        members[0] = (0x02, Value::Raw(descriptor));
    }
    if let Some(user) = user {
        members.push((0x03, user));
    }
    sub_params(&members)
}

/// A user entity with `id` and the names given.
fn user_entity(id: &[u8], name: Option<&'static str>, display_name: Option<&'static str>) -> Value {
    let members = 1 + usize::from(name.is_some()) + usize::from(display_name.is_some());
    Value::Raw(encoded(|encoder| {
        encoder.map(members).expect("room");
        encoder.text("id").expect("room").bytes(id).expect("room");
        if let Some(name) = name {
            encoder
                .text("name")
                .expect("room")
                .text(name)
                .expect("room");
        }
        if let Some(display_name) = display_name {
            encoder
                .text("displayName")
                .expect("room")
                .text(display_name)
                .expect("room");
        }
    }))
}

/// Runs `request` for a user who answers `answer`; returns the response and the screens.
fn send(
    authenticator: &mut TestAuthenticator,
    request: &[u8],
    answer: Answer,
    now_ms: u64,
) -> (Vec<u8>, Vec<(Asked, u32)>) {
    let mut ui = Scripted::new(answer);
    ui.now_ms = now_ms;
    let response = run(authenticator, &mut ui, request);
    (response, ui.asked)
}

/// What a credential management response holds.
#[derive(Debug, Default, PartialEq, Eq)]
struct Managed {
    existing: Option<u64>,
    remaining: Option<u64>,
    rp_id: Option<String>,
    rp_id_hash: Option<Vec<u8>>,
    total_rps: Option<u64>,
    /// `user` as `(id, name, displayName)`.
    user: Option<(Vec<u8>, Option<String>, Option<String>)>,
    credential_id: Option<Vec<u8>>,
    /// The public key, uncompressed SEC1.
    public_key: Option<Vec<u8>>,
    total_credentials: Option<u64>,
    cred_protect: Option<u64>,
}

fn managed(body: &[u8]) -> Managed {
    let mut decoder = Decoder::new(body);
    let managed = decoder
        .map(|entries| {
            let mut managed = Managed::default();
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => managed.existing = Some(value.unsigned()?),
                    Key::Int(2) => managed.remaining = Some(value.unsigned()?),
                    Key::Int(3) => {
                        managed.rp_id = value.map(|members| {
                            let mut id = None;
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("id") => id = Some(member.text()?.into()),
                                    _ => panic!("unexpected rp member"),
                                }
                            }
                            Ok(id)
                        })?;
                    }
                    Key::Int(4) => managed.rp_id_hash = Some(value.bytes()?.to_vec()),
                    Key::Int(5) => managed.total_rps = Some(value.unsigned()?),
                    Key::Int(6) => {
                        managed.user = Some(value.map(|members| {
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
                    Key::Int(7) => {
                        managed.credential_id = value.map(|members| {
                            let mut id = None;
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("id") => id = Some(member.bytes()?.to_vec()),
                                    Key::Text("type") => assert_eq!(member.text()?, "public-key"),
                                    _ => panic!("unexpected descriptor member"),
                                }
                            }
                            Ok(id)
                        })?;
                    }
                    Key::Int(8) => {
                        let mut point = vec![0x04; 65];
                        value.map(|cose| {
                            while let Some(key) = cose.next_key()? {
                                let member = cose.value();
                                match key {
                                    Key::Int(-2) => point[1..33].copy_from_slice(member.bytes()?),
                                    Key::Int(-3) => point[33..].copy_from_slice(member.bytes()?),
                                    _ => member.skip()?,
                                }
                            }
                            Ok(())
                        })?;
                        managed.public_key = Some(point);
                    }
                    Key::Int(9) => managed.total_credentials = Some(value.unsigned()?),
                    Key::Int(10) => managed.cred_protect = Some(value.unsigned()?),
                    _ => panic!("unexpected response member"),
                }
            }
            Ok(managed)
        })
        .expect("a response map");
    decoder.finish().expect("one item");
    managed
}

/// A getAssertion for `rp_id` with the allowList `ids`, with built-in UV.
fn assertion(rp_id: &'static str, ids: Option<&[&[u8]]>) -> Vec<u8> {
    let mut members = vec![
        (0x01, Value::Text(rp_id)),
        (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
    ];
    if let Some(ids) = ids {
        members.push((0x03, descriptors(ids)));
    }
    members.push((0x05, options(&[("uv", true)])));
    command(0x02, &members)
}

/// getCredsMetadata (§6.8.2) counts the discoverable credentials and how many more fit; a token
/// is required (no pinUvAuthParam: PUAT_REQUIRED), its MAC must verify over the subcommand, it
/// must carry `cm`, and it may not be bound to an RP, since the subcommand covers all of them.
#[test]
fn metadata_needs_an_unbound_cm_token() {
    let mut authenticator = authenticator_with_room(4, 2);
    register(&mut authenticator, RP_ID, b"user-1", true, None);
    register(&mut authenticator, RP_ID, b"user-2", false, None);
    let token_cm = token(&mut authenticator, CM, None);
    let (response, asked) = send(
        &mut authenticator,
        &request(0x01, None, &token_cm),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    assert_eq!(asked, [], "no screen");
    let metadata = managed(&response[1..]);
    assert_eq!(metadata.existing, Some(1), "only the discoverable one");
    assert_eq!(metadata.remaining, Some(3));

    let no_param = command(0x0A, &[(0x01, Value::Uint(1)), (0x03, Value::Uint(2))]);
    assert_eq!(
        send(&mut authenticator, &no_param, Answer::Confirmed, 0).0,
        [PUAT_REQUIRED]
    );
    let wrong = request(0x01, None, &[0x5A; 32]);
    assert_eq!(
        send(&mut authenticator, &wrong, Answer::Confirmed, 0).0,
        [PIN_AUTH_INVALID]
    );
    let token_ga = token(&mut authenticator, GA, Some(RP_ID));
    let without_cm = request(0x01, None, &token_ga);
    assert_eq!(
        send(&mut authenticator, &without_cm, Answer::Confirmed, 0).0,
        [PIN_AUTH_INVALID]
    );
    let token_bound = token(&mut authenticator, CM, Some(RP_ID));
    let bound = request(0x01, None, &token_bound);
    assert_eq!(
        send(&mut authenticator, &bound, Answer::Confirmed, 0).0,
        [PIN_AUTH_INVALID]
    );
    let unknown_protocol = command(
        0x0A,
        &[
            (0x01, Value::Uint(1)),
            (0x03, Value::Uint(9)),
            (0x04, Value::Bytes(vec![0; 32])),
        ],
    );
    assert_eq!(
        send(&mut authenticator, &unknown_protocol, Answer::Confirmed, 0).0,
        [INVALID_PARAMETER]
    );
}

/// A subcommand §6.8 does not define is INVALID_SUBCOMMAND, a request without one
/// MISSING_PARAMETER, and a subcommand without its parameters MISSING_PARAMETER.
#[test]
fn subcommands_and_their_parameters_are_checked() {
    let mut authenticator = authenticator_with_room(4, 2);
    let token_cm = token(&mut authenticator, CM, None);
    let unknown = request(0x08, None, &token_cm);
    assert_eq!(
        send(&mut authenticator, &unknown, Answer::Confirmed, 0).0,
        [INVALID_SUBCOMMAND]
    );
    let none = command(0x0A, &[(0x03, Value::Uint(2))]);
    assert_eq!(
        send(&mut authenticator, &none, Answer::Confirmed, 0).0,
        [MISSING_PARAMETER]
    );
    for sub_command in [0x04, 0x06, 0x07] {
        let bare = request(sub_command, None, &token_cm);
        assert_eq!(
            send(&mut authenticator, &bare, Answer::Confirmed, 0).0,
            [MISSING_PARAMETER],
            "subcommand {sub_command}"
        );
    }
}

/// enumerateRPsBegin and enumerateRPsGetNextRP (§6.8.3) return every RP once, the first with the
/// number of RPs, each with its RP ID and hash; after the last, without a begin, after another
/// command, or more than 30 seconds after the last call, the continuation is NOT_ALLOWED. With no
/// discoverable credential the begin is NO_CREDENTIALS.
#[test]
fn rps_enumerate_across_many_rps() {
    let mut authenticator = authenticator_with_room(8, 2);
    let token_cm = token(&mut authenticator, CM, None);
    let begin = request(0x02, None, &token_cm);
    assert_eq!(
        send(&mut authenticator, &begin, Answer::Confirmed, 0).0,
        [NO_CREDENTIALS]
    );

    let rps = ["a.example", "b.example", "c.example"];
    for (index, rp_id) in rps.iter().enumerate() {
        for user in 0..=index {
            register(&mut authenticator, rp_id, &[b'u', user as u8], true, None);
        }
    }
    let token_cm = token(&mut authenticator, CM, None);
    let (response, _) = send(
        &mut authenticator,
        &request(0x02, None, &token_cm),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    let first = managed(&response[1..]);
    assert_eq!(first.total_rps, Some(3));
    let mut seen = vec![first.rp_id.clone().expect("rp")];
    assert_eq!(first.rp_id_hash, Some(Sha256::digest(&seen[0]).to_vec()));
    for _ in 1..3 {
        let (response, _) = send(&mut authenticator, &next(0x03), Answer::Confirmed, 1_000);
        assert_eq!(response[0], OK);
        let rp = managed(&response[1..]);
        assert_eq!(rp.total_rps, None, "only the first carries the total");
        let rp_id = rp.rp_id.expect("rp");
        assert_eq!(rp.rp_id_hash, Some(Sha256::digest(&rp_id).to_vec()));
        seen.push(rp_id);
    }
    seen.sort_unstable();
    assert_eq!(seen, rps);
    assert_eq!(
        send(&mut authenticator, &next(0x03), Answer::Confirmed, 1_000).0,
        [NOT_ALLOWED]
    );

    // A credential continuation does not go on from an RP enumeration, and another command ends it.
    send(
        &mut authenticator,
        &request(0x02, None, &token_cm),
        Answer::Confirmed,
        2_000,
    );
    assert_eq!(
        send(&mut authenticator, &next(0x05), Answer::Confirmed, 2_000).0,
        [NOT_ALLOWED]
    );
    send(
        &mut authenticator,
        &request(0x02, None, &token_cm),
        Answer::Confirmed,
        2_000,
    );
    send(&mut authenticator, &[0x04], Answer::Confirmed, 2_000);
    assert_eq!(
        send(&mut authenticator, &next(0x03), Answer::Confirmed, 2_000).0,
        [NOT_ALLOWED]
    );
    send(
        &mut authenticator,
        &request(0x02, None, &token_cm),
        Answer::Confirmed,
        3_000,
    );
    let late = 3_000 + NEXT_ASSERTION_TIMEOUT_MS + 1;
    assert_eq!(
        send(&mut authenticator, &next(0x03), Answer::Confirmed, late).0,
        [NOT_ALLOWED]
    );
}

/// enumerateCredentialsBegin and enumerateCredentialsGetNextCredential (§6.8.4) return an RP's
/// credentials newest first, each with its user and every name, its ID, its public key and its
/// credProtect level, the first with the number of them; an RP without credentials is
/// NO_CREDENTIALS. A token bound to the RP may enumerate it, one bound to another may not.
#[test]
fn credentials_of_an_rp_enumerate_with_their_members() {
    let mut authenticator = authenticator_with_room(8, 2);
    let older = register(
        &mut authenticator,
        RP_ID,
        b"user-1",
        true,
        Some(Origin::DeviceOnly),
    );
    let newer = register(
        &mut authenticator,
        RP_ID,
        b"user-2",
        true,
        Some(Origin::SeedRecoverable),
    );
    register(&mut authenticator, "other.example", b"user-3", true, None);
    let token_cm = token(&mut authenticator, CM, None);
    let params = rp_hash_params(RP_ID);
    let (response, _) = send(
        &mut authenticator,
        &request(0x04, Some(&params), &token_cm),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    let first = managed(&response[1..]);
    assert_eq!(first.total_credentials, Some(2));
    let expect = |listed: &Managed, made: &Made, user_id: &[u8]| {
        assert_eq!(listed.credential_id.as_deref(), Some(&made.id[..]));
        assert_eq!(listed.public_key.as_deref(), Some(&made.public_key[..]));
        assert_eq!(
            listed.user,
            Some((user_id.to_vec(), Some("alice".into()), Some("Alice".into())))
        );
        assert_eq!(listed.cred_protect, Some(1));
    };
    expect(&first, &newer, b"user-2");
    let (response, _) = send(&mut authenticator, &next(0x05), Answer::Confirmed, 0);
    assert_eq!(response[0], OK);
    let second = managed(&response[1..]);
    assert_eq!(second.total_credentials, None);
    expect(&second, &older, b"user-1");
    assert_eq!(
        send(&mut authenticator, &next(0x05), Answer::Confirmed, 0).0,
        [NOT_ALLOWED]
    );

    let missing = rp_hash_params("missing.example");
    assert_eq!(
        send(
            &mut authenticator,
            &request(0x04, Some(&missing), &token_cm),
            Answer::Confirmed,
            0
        )
        .0,
        [NO_CREDENTIALS]
    );
    let token_this = token(&mut authenticator, CM, Some(RP_ID));
    assert_eq!(
        send(
            &mut authenticator,
            &request(0x04, Some(&params), &token_this),
            Answer::Confirmed,
            0
        )
        .0[0],
        OK
    );
    let token_other = token(&mut authenticator, CM, Some("other.example"));
    assert_eq!(
        send(
            &mut authenticator,
            &request(0x04, Some(&params), &token_other),
            Answer::Confirmed,
            0
        )
        .0,
        [PIN_AUTH_INVALID]
    );
}

/// deleteCredential (§6.8.5) of either origin asks the user on the device, naming the RP and the
/// account; once confirmed the credential no longer enumerates and no longer signs, also from an
/// allowList with its ID (§6.1.3). A refusal or no answer deletes nothing; an ID no discoverable
/// credential has is NO_CREDENTIALS; a token bound to another RP is PIN_AUTH_INVALID.
#[test]
fn deleting_a_credential_of_either_origin() {
    for origin in [Origin::SeedRecoverable, Origin::DeviceOnly] {
        let mut authenticator = authenticator_with_room(4, 2);
        let made = register(&mut authenticator, RP_ID, b"user-1", true, Some(origin));
        let kept = register(&mut authenticator, RP_ID, b"user-2", true, Some(origin));
        let token_cm = token(&mut authenticator, CM, None);
        let params = credential_params(&made.id, None);
        let delete = request(0x06, Some(&params), &token_cm);

        for (answer, status) in [
            (Answer::Rejected, OPERATION_DENIED),
            (Answer::TimedOut, USER_ACTION_TIMEOUT),
        ] {
            assert_eq!(
                send(&mut authenticator, &delete, answer, 0).0,
                [status],
                "{origin:?}"
            );
        }
        let token_other = token(&mut authenticator, CM, Some("other.example"));
        let foreign = request(0x06, Some(&params), &token_other);
        assert_eq!(
            send(&mut authenticator, &foreign, Answer::Confirmed, 0).0,
            [PIN_AUTH_INVALID]
        );

        let token_cm = token(&mut authenticator, CM, None);
        let delete = request(0x06, Some(&params), &token_cm);
        let (response, asked) = send(&mut authenticator, &delete, Answer::Confirmed, 0);
        assert_eq!(response, [OK], "{origin:?}");
        assert_eq!(
            asked,
            [(
                Asked::Delete {
                    rp_id: RP_ID.into(),
                    account: Shown {
                        name: Some("alice".into()),
                        display_name: Some("Alice".into()),
                        origin: Some(origin),
                    },
                },
                USER_ACTION_TIMEOUT_MS
            )]
        );
        assert_eq!(
            send(&mut authenticator, &delete, Answer::Confirmed, 0).0,
            [NO_CREDENTIALS]
        );

        let listed = request(0x04, Some(&rp_hash_params(RP_ID)), &token_cm);
        let (response, _) = send(&mut authenticator, &listed, Answer::Confirmed, 0);
        let only = managed(&response[1..]);
        assert_eq!(only.total_credentials, Some(1));
        assert_eq!(only.credential_id.as_deref(), Some(&kept.id[..]));
        let (response, _) = send(
            &mut authenticator,
            &assertion(RP_ID, Some(&[&made.id])),
            Answer::Confirmed,
            0,
        );
        assert_eq!(response, [NO_CREDENTIALS], "{origin:?}");
    }
}

/// updateUserInformation (§6.8.6) gives a credential new names, an absent one removed; its user ID
/// must stay (INVALID_PARAMETER otherwise). The ID the RP holds is unchanged and signs with the new
/// names in the response; enumeration and the account picker show them. With every name slot
/// taken by other credentials the update is KEY_STORE_FULL, and a further update of the same
/// credential needs no new slot.
#[test]
fn updating_user_names() {
    let mut authenticator = authenticator_with_room(4, 1);
    let made = register(&mut authenticator, RP_ID, b"user-1", true, None);
    let other = register(&mut authenticator, RP_ID, b"user-2", true, None);
    let token_cm = token(&mut authenticator, CM, None);
    let update =
        |id: &[u8], user_id: &[u8], name: Option<&'static str>, display: Option<&'static str>| {
            request(
                0x07,
                Some(&credential_params(
                    id,
                    Some(user_entity(user_id, name, display)),
                )),
                &token_cm,
            )
        };
    assert_eq!(
        send(
            &mut authenticator,
            &update(&made.id, b"user-9", Some("bob"), None),
            Answer::Confirmed,
            0
        )
        .0,
        [INVALID_PARAMETER]
    );
    let (response, asked) = send(
        &mut authenticator,
        &update(&made.id, b"user-1", Some("bob"), None),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response, [OK]);
    assert_eq!(asked, [], "no screen");
    assert_eq!(
        send(
            &mut authenticator,
            &update(&made.id, b"user-1", Some("bobby"), Some("Bob")),
            Answer::Confirmed,
            0
        )
        .0,
        [OK],
        "its own slot again"
    );
    assert_eq!(
        send(
            &mut authenticator,
            &update(&other.id, b"user-2", Some("carol"), None),
            Answer::Confirmed,
            0
        )
        .0,
        [KEY_STORE_FULL]
    );

    let listed = request(0x04, Some(&rp_hash_params(RP_ID)), &token_cm);
    let (response, _) = send(&mut authenticator, &listed, Answer::Confirmed, 0);
    let first = managed(&response[1..]);
    let (response, _) = send(&mut authenticator, &next(0x05), Answer::Confirmed, 0);
    let second = managed(&response[1..]);
    let renamed = [first, second]
        .into_iter()
        .find(|listed| listed.credential_id.as_deref() == Some(&made.id[..]))
        .expect("listed");
    assert_eq!(
        renamed.user,
        Some((b"user-1".to_vec(), Some("bobby".into()), Some("Bob".into())))
    );

    let (response, _) = send(
        &mut authenticator,
        &assertion(RP_ID, Some(&[&made.id])),
        Answer::Confirmed,
        0,
    );
    assert_eq!(response[0], OK);
    let mut decoder = Decoder::new(&response[1..]);
    let (id, user) = decoder
        .map(|entries| {
            let mut id = Vec::new();
            let mut names = Vec::new();
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => {
                        value.map(|members| {
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                if key == Key::Text("id") {
                                    id = member.bytes()?.to_vec();
                                } else {
                                    member.skip()?;
                                }
                            }
                            Ok(())
                        })?;
                    }
                    Key::Int(4) => {
                        value.map(|members| {
                            while let Some(key) = members.next_key()? {
                                let member = members.value();
                                match key {
                                    Key::Text("name" | "displayName") => {
                                        names.push(String::from(member.text()?));
                                    }
                                    _ => member.skip()?,
                                }
                            }
                            Ok(())
                        })?;
                    }
                    _ => value.skip()?,
                }
            }
            Ok((id, names))
        })
        .expect("a response map");
    assert_eq!(id, made.id, "the ID the RP holds");
    assert_eq!(user, ["bobby", "Bob"]);

    let (_, asked) = send(
        &mut authenticator,
        &assertion(RP_ID, None),
        Answer::Confirmed,
        0,
    );
    let Some((Asked::Pick { accounts, .. }, _)) = asked.first() else {
        panic!("the account picker: {asked:?}");
    };
    assert!(
        accounts
            .iter()
            .any(|account| account.name.as_deref() == Some("bobby")),
        "{accounts:?}"
    );

    // The assertions cleared the token's permissions (§6.2.2 step 11.4), so a new one follows.
    // Deleting the renamed credential frees its name slot for the other one.
    let token_cm = token(&mut authenticator, CM, None);
    let delete = request(0x06, Some(&credential_params(&made.id, None)), &token_cm);
    assert_eq!(
        send(&mut authenticator, &delete, Answer::Confirmed, 0).0,
        [OK]
    );
    let update = request(
        0x07,
        Some(&credential_params(
            &other.id,
            Some(user_entity(b"user-2", None, None)),
        )),
        &token_cm,
    );
    assert_eq!(
        send(&mut authenticator, &update, Answer::Confirmed, 0).0,
        [OK]
    );
    let listed = request(0x04, Some(&rp_hash_params(RP_ID)), &token_cm);
    let (response, _) = send(&mut authenticator, &listed, Answer::Confirmed, 0);
    assert_eq!(
        managed(&response[1..]).user,
        Some((b"user-2".to_vec(), None, None)),
        "both names removed"
    );
}

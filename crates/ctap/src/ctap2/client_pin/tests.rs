//! authenticatorClientPIN against CTAP 2.2 §6.5.5, end to end through the authenticator. The
//! platform side (ECDH, the protocols' key derivation, encryption and MACs) is computed here with
//! the RustCrypto crates, apart from the code under test.

use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

use super::super::tests::{Asked, Scripted, TestAuthenticator, authenticator};
use crate::cbor::{Decoder, Encoder, Key};
use crate::crypto::Crypto;
use crate::pin::{INITIAL_USAGE_TIME_LIMIT_MS, Permissions, Protocol};
use crate::ui::{Answer, USER_ACTION_TIMEOUT_MS, Verification};

const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
const MISSING_PARAMETER: u8 = 0x14;
const OPERATION_DENIED: u8 = 0x27;
const KEEPALIVE_CANCEL: u8 = 0x2D;
const USER_ACTION_TIMEOUT: u8 = 0x2F;
const PIN_INVALID: u8 = 0x31;
const PIN_BLOCKED: u8 = 0x32;
const PIN_AUTH_INVALID: u8 = 0x33;
const PIN_AUTH_BLOCKED: u8 = 0x34;
const PIN_NOT_SET: u8 = 0x35;
const PIN_POLICY_VIOLATION: u8 = 0x37;
const UV_BLOCKED: u8 = 0x3C;
const INVALID_SUBCOMMAND: u8 = 0x3E;
const UV_INVALID: u8 = 0x3F;
const UNAUTHORIZED_PERMISSION: u8 = 0x40;

/// A member value of a request.
enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(&'static str),
    /// Already encoded CBOR, written as is.
    Raw(Vec<u8>),
}

/// One item written by `write`, encoded.
fn encoded(write: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut buffer = [0u8; 512];
    let mut encoder = Encoder::new(&mut buffer);
    write(&mut encoder);
    encoder.as_bytes().to_vec()
}

/// An authenticatorClientPIN request with `members`, given in canonical key order.
fn request(members: &[(u64, Value)]) -> Vec<u8> {
    let mut message = vec![0x06];
    message.extend(encoded(|encoder| {
        encoder.map(members.len()).expect("room");
    }));
    for (key, value) in members {
        message.extend(encoded(|encoder| {
            encoder.unsigned(*key).expect("room");
        }));
        match value {
            Value::Raw(raw) => message.extend_from_slice(raw),
            Value::Uint(value) => message.extend(encoded(|encoder| {
                encoder.unsigned(*value).expect("room");
            })),
            Value::Bytes(value) => message.extend(encoded(|encoder| {
                encoder.bytes(value).expect("room");
            })),
            Value::Text(value) => message.extend(encoded(|encoder| {
                encoder.text(value).expect("room");
            })),
        }
    }
    message
}

fn run(authenticator: &mut TestAuthenticator, ui: &mut Scripted, request: &[u8]) -> Vec<u8> {
    let mut response = [0u8; 512];
    let length = authenticator.process(request, ui, &mut response);
    response[..length].to_vec()
}

/// The response map's members: COSE key points, byte strings, integers and booleans by key.
#[derive(Debug, Default)]
struct Response {
    key_agreement: Option<[u8; 65]>,
    token: Option<Vec<u8>>,
    pin_retries: Option<u64>,
    power_cycle: Option<bool>,
    uv_retries: Option<u64>,
}

fn parse_response(body: &[u8]) -> Response {
    let mut decoder = Decoder::new(body);
    let response = decoder
        .map(|entries| {
            let mut response = Response::default();
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                match key {
                    Key::Int(1) => {
                        let mut point = [0u8; 65];
                        point[0] = 0x04;
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
                        response.key_agreement = Some(point);
                    }
                    Key::Int(2) => response.token = Some(value.bytes()?.to_vec()),
                    Key::Int(3) => response.pin_retries = Some(value.unsigned()?),
                    Key::Int(4) => response.power_cycle = Some(value.bool()?),
                    Key::Int(5) => response.uv_retries = Some(value.unsigned()?),
                    _ => value.skip()?,
                }
            }
            Ok(response)
        })
        .expect("a CBOR map");
    decoder.finish().expect("one message");
    response
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn hkdf(z: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), z)
        .expand(info, &mut out)
        .expect("32 bytes");
    out
}

fn cbc(key: &[u8; 32], iv: &[u8; 16], data: &[u8], encrypt: bool) -> Vec<u8> {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _};
    let cipher = aes::Aes256::new(key.into());
    let mut previous = *iv;
    let mut out = Vec::new();
    for chunk in data.chunks(16) {
        let mut block = aes::Block::default();
        if encrypt {
            for ((byte, &plain), &chain) in block.iter_mut().zip(chunk).zip(&previous) {
                *byte = plain ^ chain;
            }
            cipher.encrypt_block(&mut block);
            previous.copy_from_slice(&block);
            out.extend_from_slice(&block);
        } else {
            block.copy_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for (&plain, &chain) in block.iter().zip(&previous) {
                out.push(plain ^ chain);
            }
            previous.copy_from_slice(chunk);
        }
    }
    out
}

/// The platform's half of one key agreement (§6.5.5.4): its key as a COSE_Key and the shared
/// secret's two keys.
struct Session {
    protocol: Protocol,
    cose_key: Vec<u8>,
    hmac_key: [u8; 32],
    aes_key: [u8; 32],
}

/// The IV the platform uses with protocol two; any 16 bytes do.
const IV: [u8; 16] = [0x99; 16];

impl Session {
    /// getKeyAgreement, then ECDH with a fixed platform key and the protocol's kdf.
    fn start(authenticator: &mut TestAuthenticator, protocol: Protocol) -> Self {
        let mut ui = Scripted::new(Answer::Confirmed);
        let response = run(
            authenticator,
            &mut ui,
            &request(&[
                (0x01, Value::Uint(protocol as u64)),
                (0x02, Value::Uint(0x02)),
            ]),
        );
        assert_eq!(response[0], OK);
        let device = parse_response(&response[1..])
            .key_agreement
            .expect("keyAgreement");
        let platform = p256::SecretKey::from_slice(&[0x5E; 32]).expect("valid scalar");
        let point = platform.public_key().to_sec1_point(false);
        let device = p256::PublicKey::from_sec1_bytes(&device).expect("on the curve");
        let z = p256::ecdh::diffie_hellman(platform.to_nonzero_scalar(), device.as_affine());
        let z = z.raw_secret_bytes();
        let (hmac_key, aes_key) = match protocol {
            Protocol::One => {
                let key: [u8; 32] = Sha256::digest(z).into();
                (key, key)
            }
            Protocol::Two => (hkdf(z, b"CTAP2 HMAC key"), hkdf(z, b"CTAP2 AES key")),
        };
        // {1: 2, 3: -25, -1: 1, -2: x, -3: y}
        let mut cose_key = vec![
            0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
        ];
        cose_key.extend_from_slice(&point.as_bytes()[1..33]);
        cose_key.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose_key.extend_from_slice(&point.as_bytes()[33..]);
        Self {
            protocol,
            cose_key,
            hmac_key,
            aes_key,
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        match self.protocol {
            Protocol::One => cbc(&self.aes_key, &[0; 16], plaintext, true),
            Protocol::Two => {
                let mut out = IV.to_vec();
                out.extend(cbc(&self.aes_key, &IV, plaintext, true));
                out
            }
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self.protocol {
            Protocol::One => cbc(&self.aes_key, &[0; 16], ciphertext, false),
            Protocol::Two => {
                let iv: [u8; 16] = ciphertext[..16].try_into().expect("an IV");
                cbc(&self.aes_key, &iv, &ciphertext[16..], false)
            }
        }
    }

    fn authenticate(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mac = hmac(&self.hmac_key, parts);
        mac[..self.protocol.signature_len()].to_vec()
    }

    fn key_agreement(&self) -> Value {
        Value::Raw(self.cose_key.clone())
    }
}

fn padded(pin: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; 64];
    padded[..pin.len()].copy_from_slice(pin);
    padded
}

fn pin_hash(pin: &[u8]) -> Vec<u8> {
    Sha256::digest(pin)[..16].to_vec()
}

/// setPIN with `pin` over a fresh key agreement; returns the status.
fn set_pin(authenticator: &mut TestAuthenticator, protocol: Protocol, pin: &[u8]) -> u8 {
    let session = Session::start(authenticator, protocol);
    let new_pin_enc = session.encrypt(&padded(pin));
    let param = session.authenticate(&[&new_pin_enc]);
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        authenticator,
        &mut ui,
        &request(&[
            (0x01, Value::Uint(protocol as u64)),
            (0x02, Value::Uint(0x03)),
            (0x03, session.key_agreement()),
            (0x04, Value::Bytes(param)),
            (0x05, Value::Bytes(new_pin_enc)),
        ]),
    );
    assert_eq!(ui.asked, [], "setPIN shows no screen");
    response[0]
}

/// getPinToken (0x05) or getPinUvAuthTokenUsingPinWithPermissions (0x09) with `pin`, for a user
/// who gives `ui`'s answers; returns the response and the session.
fn pin_token(
    authenticator: &mut TestAuthenticator,
    ui: &mut Scripted,
    protocol: Protocol,
    pin: &[u8],
    permissions: Option<u64>,
    rp_id: Option<&'static str>,
) -> (Vec<u8>, Session) {
    let session = Session::start(authenticator, protocol);
    let mut members = vec![
        (0x01, Value::Uint(protocol as u64)),
        (
            0x02,
            Value::Uint(if permissions.is_some() { 0x09 } else { 0x05 }),
        ),
        (0x03, session.key_agreement()),
        (0x06, Value::Bytes(session.encrypt(&pin_hash(pin)))),
    ];
    if let Some(permissions) = permissions {
        members.push((0x09, Value::Uint(permissions)));
    }
    if let Some(rp_id) = rp_id {
        members.push((0x0A, Value::Text(rp_id)));
    }
    let response = run(authenticator, ui, &request(&members));
    (response, session)
}

fn retries(authenticator: &mut TestAuthenticator) -> (u64, bool) {
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x01))]),
    );
    assert_eq!(response[0], OK);
    let response = parse_response(&response[1..]);
    (
        response.pin_retries.expect("pinRetries"),
        response.power_cycle.expect("powerCycleState"),
    )
}

/// A parsed request owns copies of newPinEnc and pinHashEnc, which with the key agreement key
/// recover the PIN, so it wipes its buffers when dropped, on every path.
#[test]
fn a_request_wipes_its_members_when_dropped() {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<super::ClientPinRequest>();
    wiped_on_drop::<super::Bytes<32>>();
}

/// getKeyAgreement returns the COSE_Key of §6.5.6 getPublicKey: {1: 2, 3: -25, -1: 1, -2: x,
/// -3: y}, keys in canonical order, for each protocol its own key.
#[test]
fn get_key_agreement_returns_the_cose_key() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut points = Vec::new();
    for protocol in [1, 2] {
        let response = run(
            &mut authenticator,
            &mut ui,
            &request(&[(0x01, Value::Uint(protocol)), (0x02, Value::Uint(0x02))]),
        );
        assert_eq!(
            response[..13],
            [
                0x00, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58
            ]
        );
        assert_eq!(response[13], 0x20, "x is 32 bytes");
        assert_eq!(response[46..49], [0x22, 0x58, 0x20], "-3: 32-byte y");
        assert_eq!(response.len(), 81);
        let point = parse_response(&response[1..]).key_agreement.expect("key");
        assert!(
            p256::PublicKey::from_sec1_bytes(&point).is_ok(),
            "on the curve"
        );
        points.push(point);
    }
    assert_ne!(points[0], points[1]);
    assert_eq!(ui.asked, []);
}

/// §6.5.5.4 steps 3 and 4: getKeyAgreement without pinUvAuthProtocol is MISSING_PARAMETER, with
/// an unsupported one INVALID_PARAMETER.
#[test]
fn get_key_agreement_needs_a_supported_protocol() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let missing = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x02))]),
    );
    assert_eq!(missing, [MISSING_PARAMETER]);
    let unsupported = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x01, Value::Uint(3)), (0x02, Value::Uint(0x02))]),
    );
    assert_eq!(unsupported, [INVALID_PARAMETER]);
}

/// A request without subCommand is MISSING_PARAMETER; an unknown one INVALID_SUBCOMMAND (§6.5.5).
#[test]
fn sub_command_is_required_and_known() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    assert_eq!(
        run(
            &mut authenticator,
            &mut ui,
            &request(&[(0x01, Value::Uint(2))])
        ),
        [MISSING_PARAMETER]
    );
    for sub_command in [0x00, 0x08, 0x0A, 0xFF] {
        assert_eq!(
            run(
                &mut authenticator,
                &mut ui,
                &request(&[(0x02, Value::Uint(sub_command))])
            ),
            [INVALID_SUBCOMMAND],
            "{sub_command:#x}"
        );
    }
}

/// getPINRetries on fresh NVM answers {3: 8, 4: false}: eight retries (§6.5.2.3 allows at most
/// eight) and no power cycle needed.
#[test]
fn get_pin_retries_on_fresh_nvm() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x01))]),
    );
    assert_eq!(response, [0x00, 0xA2, 0x03, 0x08, 0x04, 0xF4]);
}

/// setPIN stores the PIN for either protocol; a second setPIN is PIN_AUTH_INVALID (§6.5.5.5
/// step 5.3). The PIN then opens getPinToken.
#[test]
fn set_pin_then_get_a_token() {
    for protocol in [Protocol::One, Protocol::Two] {
        let mut authenticator = authenticator();
        assert_eq!(
            set_pin(&mut authenticator, protocol, b"1234"),
            OK,
            "{protocol:?}"
        );
        assert_eq!(retries(&mut authenticator), (8, false));
        assert_eq!(
            set_pin(&mut authenticator, protocol, b"5678"),
            PIN_AUTH_INVALID,
            "{protocol:?}"
        );

        let mut ui = Scripted::new(Answer::Confirmed);
        let (response, session) =
            pin_token(&mut authenticator, &mut ui, protocol, b"1234", None, None);
        assert_eq!(response[0], OK, "{protocol:?}");
        let token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));
        assert_eq!(token, authenticator.client_pin.token(protocol)[..]);
        // §6.5.5.7.1: consent to the default permissions, mc and ga, without an RP ID.
        assert_eq!(
            ui.asked,
            [(
                Asked::Token {
                    permissions: 0x03,
                    rp_id: None
                },
                USER_ACTION_TIMEOUT_MS
            )]
        );
        assert!(
            authenticator
                .client_pin
                .has_permission(Permissions::DEFAULT)
        );
        // The platform authenticates with the token: §6.5.6 `verify` with the token as key.
        let client_data_hash = [0x0C; 32];
        let param = hmac(&token, &[&client_data_hash])[..protocol.signature_len()].to_vec();
        assert!(authenticator.client_pin.verify_token(
            &authenticator.crypto,
            protocol,
            &[&client_data_hash],
            &param,
            1
        ));
    }
}

/// setPIN refusals (§6.5.5.5): a missing member, an unusable platform key, a wrong MAC, a padded
/// PIN of another length, and PINs the policy refuses. None of them sets a PIN.
#[test]
fn set_pin_refusals() {
    let mut authenticator = authenticator();
    let session = Session::start(&mut authenticator, Protocol::Two);
    let new_pin_enc = session.encrypt(&padded(b"1234"));
    let param = session.authenticate(&[&new_pin_enc]);
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut send = |members: &[(u64, Value)]| run(&mut authenticator, &mut ui, &request(members));

    // No pinUvAuthParam.
    assert_eq!(
        send(&[
            (0x01, Value::Uint(2)),
            (0x02, Value::Uint(0x03)),
            (0x03, session.key_agreement()),
            (0x05, Value::Bytes(new_pin_enc.clone())),
        ]),
        [MISSING_PARAMETER]
    );
    // A key agreement key that is no EC2 key: kty 1.
    let mut bad_key = session.cose_key.clone();
    bad_key[2] = 0x01;
    assert_eq!(
        send(&[
            (0x01, Value::Uint(2)),
            (0x02, Value::Uint(0x03)),
            (0x03, Value::Raw(bad_key)),
            (0x04, Value::Bytes(param.clone())),
            (0x05, Value::Bytes(new_pin_enc.clone())),
        ]),
        [INVALID_PARAMETER]
    );
    // A key agreement key without alg, one with alg -7 instead of -25, and one with a further
    // optional parameter, key_ops (label 4): §6.5.6 ecdh parses the key as getPublicKey specifies
    // it, alg present and no other optional parameter (§6.5.5, keyAgreement).
    let point = &session.cose_key[11..];
    let no_alg = [&[0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20][..], point].concat();
    let es256 = [
        &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20][..],
        point,
    ]
    .concat();
    let key_ops = [
        &[
            0xA6, 0x01, 0x02, 0x03, 0x38, 0x18, 0x04, 0x81, 0x01, 0x20, 0x01, 0x21, 0x58, 0x20,
        ][..],
        point,
    ]
    .concat();
    for key in [no_alg, es256, key_ops] {
        assert_eq!(
            send(&[
                (0x01, Value::Uint(2)),
                (0x02, Value::Uint(0x03)),
                (0x03, Value::Raw(key)),
                (0x04, Value::Bytes(param.clone())),
                (0x05, Value::Bytes(new_pin_enc.clone())),
            ]),
            [INVALID_PARAMETER]
        );
    }
    // A MAC over something else.
    assert_eq!(
        send(&[
            (0x01, Value::Uint(2)),
            (0x02, Value::Uint(0x03)),
            (0x03, session.key_agreement()),
            (0x04, Value::Bytes(session.authenticate(&[b"other"]))),
            (0x05, Value::Bytes(new_pin_enc.clone())),
        ]),
        [PIN_AUTH_INVALID]
    );
    // A padded PIN of 48 bytes, correctly authenticated.
    let short = session.encrypt(&padded(b"1234")[..48]);
    assert_eq!(
        send(&[
            (0x01, Value::Uint(2)),
            (0x02, Value::Uint(0x03)),
            (0x03, session.key_agreement()),
            (0x04, Value::Bytes(session.authenticate(&[&short]))),
            (0x05, Value::Bytes(short)),
        ]),
        [INVALID_PARAMETER]
    );
    // Three digits, and 64 bytes with no padding at all.
    for pin in [padded(b"123"), vec![b'1'; 64]] {
        let encrypted = session.encrypt(&pin);
        assert_eq!(
            send(&[
                (0x01, Value::Uint(2)),
                (0x02, Value::Uint(0x03)),
                (0x03, session.key_agreement()),
                (0x04, Value::Bytes(session.authenticate(&[&encrypted]))),
                (0x05, Value::Bytes(encrypted)),
            ]),
            [PIN_POLICY_VIOLATION]
        );
    }
    assert!(authenticator.store.config().pin.is_none());
}

/// Members longer than any ciphertext of a padded PIN or PIN hash are authenticated first, in the
/// order of §6.5.5.5 and §6.5.5.6: a wrong MAC is PIN_AUTH_INVALID whatever the length. With the
/// right MAC, setPIN decrypts (an error is PIN_AUTH_INVALID) and finds no 64-byte padded PIN
/// (INVALID_PARAMETER); changePIN spends a try on a PIN hash that cannot match (PIN_INVALID).
#[test]
fn oversized_members_are_authenticated_first() {
    let mut authenticator = authenticator();
    let session = Session::start(&mut authenticator, Protocol::Two);
    // 16-byte IV and 80 bytes of ciphertext: longer than a padded PIN's 64.
    let long = session.encrypt(&[0x31; 80]);
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut set = |new_pin_enc: &[u8], param: Vec<u8>| {
        run(
            &mut authenticator,
            &mut ui,
            &request(&[
                (0x01, Value::Uint(2)),
                (0x02, Value::Uint(0x03)),
                (0x03, session.key_agreement()),
                (0x04, Value::Bytes(param)),
                (0x05, Value::Bytes(new_pin_enc.to_vec())),
            ]),
        )
    };
    assert_eq!(
        set(&long, session.authenticate(&[b"other"])),
        [PIN_AUTH_INVALID]
    );
    assert_eq!(
        set(&long, session.authenticate(&[&long])),
        [INVALID_PARAMETER]
    );
    let misaligned = &long[..long.len() - 3];
    assert_eq!(
        set(misaligned, session.authenticate(&[misaligned])),
        [PIN_AUTH_INVALID]
    );
    assert!(authenticator.store.config().pin.is_none());

    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let session = Session::start(&mut authenticator, Protocol::Two);
    // A 32-byte plaintext: longer than the 16-byte PIN hash.
    let pin_hash_enc = session.encrypt(&[0x42; 32]);
    let new_pin_enc = session.encrypt(&padded(b"98765"));
    let mut change = |authenticator: &mut TestAuthenticator, param: Vec<u8>| {
        run(
            authenticator,
            &mut ui,
            &request(&[
                (0x01, Value::Uint(2)),
                (0x02, Value::Uint(0x04)),
                (0x03, session.key_agreement()),
                (0x04, Value::Bytes(param)),
                (0x05, Value::Bytes(new_pin_enc.clone())),
                (0x06, Value::Bytes(pin_hash_enc.clone())),
            ]),
        )
    };
    assert_eq!(
        change(&mut authenticator, session.authenticate(&[b"other"])),
        [PIN_AUTH_INVALID]
    );
    assert_eq!(
        retries(&mut authenticator),
        (8, false),
        "no try for a wrong MAC"
    );
    let param = session.authenticate(&[&new_pin_enc, &pin_hash_enc]);
    assert_eq!(change(&mut authenticator, param), [PIN_INVALID]);
    assert_eq!(
        retries(&mut authenticator),
        (7, false),
        "a try for a PIN hash that cannot match"
    );
}

/// A wrong PIN spends a try (§6.5.5.7.1: decremented before the check) and is PIN_INVALID; the
/// key agreement key is regenerated. The third mismatch in a row is PIN_AUTH_BLOCKED, and from
/// then on PIN entries are refused without spending a try until a power cycle; getPINRetries
/// reports powerCycleState. A correct PIN before that restores the tries.
#[test]
fn wrong_pins_spend_tries_and_block_until_a_power_cycle() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);

    let before = *authenticator.client_pin.public_key(Protocol::Two);
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"0000",
        None,
        None,
    );
    assert_eq!(response, [PIN_INVALID]);
    assert_ne!(*authenticator.client_pin.public_key(Protocol::Two), before);
    assert_eq!(retries(&mut authenticator), (7, false));

    // A correct PIN restores the tries and ends the run of mismatches.
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        None,
        None,
    );
    assert_eq!(response[0], OK);
    assert_eq!(retries(&mut authenticator), (8, false));

    for expected in [PIN_INVALID, PIN_INVALID, PIN_AUTH_BLOCKED] {
        let (response, _) = pin_token(
            &mut authenticator,
            &mut ui,
            Protocol::Two,
            b"0000",
            None,
            None,
        );
        assert_eq!(response, [expected]);
    }
    assert_eq!(retries(&mut authenticator), (5, true));
    // Blocked until a power cycle: even the right PIN is refused, and no try is spent.
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        None,
        None,
    );
    assert_eq!(response, [PIN_AUTH_BLOCKED]);
    assert_eq!(retries(&mut authenticator), (5, true));

    // Reopening the application is the power cycle: the stored state stays, the count goes.
    let mut reopened = authenticator.reopen();
    assert_eq!(retries(&mut reopened), (5, false));
    let (response, _) = pin_token(&mut reopened, &mut ui, Protocol::Two, b"1234", None, None);
    assert_eq!(response[0], OK);
    assert_eq!(retries(&mut reopened), (8, false));
}

/// The last try spent on a wrong PIN is PIN_BLOCKED, and from then on every PIN entry is
/// PIN_BLOCKED (§6.5.5.7.1); built-in UV is disabled with it (§6.5.2.3).
#[test]
fn the_last_try_blocks_the_pin() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::One, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);
    for round in 0..8 {
        if round % 3 == 0 {
            authenticator = authenticator.reopen();
        }
        let (response, _) = pin_token(
            &mut authenticator,
            &mut ui,
            Protocol::One,
            b"0000",
            None,
            None,
        );
        let expected = match round {
            7 => PIN_BLOCKED,
            2 | 5 => PIN_AUTH_BLOCKED,
            _ => PIN_INVALID,
        };
        assert_eq!(response, [expected], "round {round}");
    }
    assert_eq!(retries(&mut authenticator).0, 0);
    let mut authenticator = authenticator.reopen();
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::One,
        b"1234",
        None,
        None,
    );
    assert_eq!(response, [PIN_BLOCKED]);

    let response = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x07))]),
    );
    assert_eq!(response, [0x00, 0xA1, 0x05, 0x00], "uvRetries 0");
}

/// §6.5.5.7.1: consent comes before the try is spent, so a consent not given costs nothing. A
/// refusal or no answer is "not approved", OPERATION_DENIED (step 7 of §6.5.5.7.1 and
/// §6.5.5.7.2); a request the host cancelled is KEEPALIVE_CANCEL (§11.2.9.1.5).
#[test]
fn consent_comes_before_the_try() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    for (answer, status) in [
        (Answer::Rejected, OPERATION_DENIED),
        (Answer::TimedOut, OPERATION_DENIED),
        (Answer::Cancelled, KEEPALIVE_CANCEL),
    ] {
        let mut ui = Scripted::new(answer);
        let (response, _) = pin_token(
            &mut authenticator,
            &mut ui,
            Protocol::Two,
            b"0000",
            None,
            None,
        );
        assert_eq!(response, [status], "{answer:?}");
    }
    assert_eq!(retries(&mut authenticator), (8, false));
}

/// getPinToken without a PIN is PIN_NOT_SET, and shows no screen.
#[test]
fn a_pin_token_without_a_pin_is_pin_not_set() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        None,
        None,
    );
    assert_eq!(response, [PIN_NOT_SET]);
    assert_eq!(ui.asked, []);
}

/// getPinToken takes no permissions and no rpId (§6.5.5.7.1): either is INVALID_PARAMETER.
#[test]
fn get_pin_token_takes_no_permissions() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let session = Session::start(&mut authenticator, Protocol::Two);
    let pin_hash_enc = session.encrypt(&pin_hash(b"1234"));
    let mut ui = Scripted::new(Answer::Confirmed);
    for extra in [
        (0x09, Value::Uint(0x03)),
        (0x0A, Value::Text("example.com")),
    ] {
        let response = run(
            &mut authenticator,
            &mut ui,
            &request(&[
                (0x01, Value::Uint(2)),
                (0x02, Value::Uint(0x05)),
                (0x03, session.key_agreement()),
                (0x06, Value::Bytes(pin_hash_enc.clone())),
                extra,
            ]),
        );
        assert_eq!(response, [INVALID_PARAMETER]);
    }
    assert_eq!(retries(&mut authenticator), (8, false));
}

/// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2): permissions 0 is INVALID_PARAMETER;
/// cm, be, lbw, acfg and pcmr are UNAUTHORIZED_PERMISSION while their features are absent; mc
/// and ga for an RP ID give a token bound to that RP, after consent naming it.
#[test]
fn a_pin_token_with_permissions_is_bound_to_its_rp() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        Some(0),
        None,
    );
    assert_eq!(response, [INVALID_PARAMETER]);
    for permission in [0x04, 0x08, 0x10, 0x20, 0x40] {
        let (response, _) = pin_token(
            &mut authenticator,
            &mut ui,
            Protocol::Two,
            b"1234",
            Some(permission),
            None,
        );
        assert_eq!(response, [UNAUTHORIZED_PERMISSION], "{permission:#x}");
    }
    assert_eq!(ui.asked, [], "refused before consent");
    assert_eq!(retries(&mut authenticator), (8, false));

    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        Some(0x03),
        Some("example.com"),
    );
    assert_eq!(response[0], OK);
    assert_eq!(
        ui.asked,
        [(
            Asked::Token {
                permissions: 0x03,
                rp_id: Some("example.com".into())
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
    let example = authenticator.crypto.sha256(&[b"example.com"]);
    let other = authenticator.crypto.sha256(&[b"other.example"]);
    assert!(authenticator.client_pin.permits_rp_id(&example));
    assert!(!authenticator.client_pin.permits_rp_id(&other));
    assert!(
        authenticator
            .client_pin
            .has_permission(Permissions::DEFAULT)
    );
    assert!(
        !authenticator.client_pin.user_present(0),
        "no presence with the client PIN"
    );
    assert!(authenticator.client_pin.user_verified(0));
}

/// The consent screen shows the whole RP ID: a control character, which would end the text at a
/// NUL or push the rest away at a line break, is shown as `?`. The token stays bound to the RP ID
/// as sent.
#[test]
fn control_characters_in_the_rp_id_are_shown() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, _) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        Some(0x02),
        Some("example.com\u{0}\n.evil.test"),
    );
    assert_eq!(response[0], OK);
    assert_eq!(
        ui.asked,
        [(
            Asked::Token {
                permissions: 0x02,
                rp_id: Some("example.com??.evil.test".into())
            },
            USER_ACTION_TIMEOUT_MS
        )]
    );
    let sent = authenticator
        .crypto
        .sha256(&[b"example.com\x00\n.evil.test"]);
    assert!(authenticator.client_pin.permits_rp_id(&sent));
}

/// A token the platform does not use within the initial usage time limit stops verifying
/// (§6.5.2.1).
#[test]
fn an_unused_token_expires() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.now_ms = 5_000;
    let (response, session) = pin_token(
        &mut authenticator,
        &mut ui,
        Protocol::Two,
        b"1234",
        None,
        None,
    );
    assert_eq!(response[0], OK);
    let token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));
    let param = hmac(&token, &[b"x"]).to_vec();
    assert!(!authenticator.client_pin.verify_token(
        &authenticator.crypto,
        Protocol::Two,
        &[b"x"],
        &param,
        5_000 + INITIAL_USAGE_TIME_LIMIT_MS
    ));
}

/// changePIN (§6.5.5.6): the current PIN's hash and the new PIN under one MAC; afterwards the
/// new PIN opens tokens, the old one does not, and tokens issued before stop verifying.
#[test]
fn change_pin_replaces_the_pin_and_its_tokens() {
    for protocol in [Protocol::One, Protocol::Two] {
        let mut authenticator = authenticator();
        assert_eq!(set_pin(&mut authenticator, protocol, b"1234"), OK);
        let mut ui = Scripted::new(Answer::Confirmed);
        let (response, session) =
            pin_token(&mut authenticator, &mut ui, protocol, b"1234", None, None);
        assert_eq!(response[0], OK);
        let old_token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));

        let change = |authenticator: &mut TestAuthenticator, current: &[u8], mac_ok: bool| {
            let session = Session::start(authenticator, protocol);
            let pin_hash_enc = session.encrypt(&pin_hash(current));
            let new_pin_enc = session.encrypt(&padded(b"98765"));
            let param = if mac_ok {
                session.authenticate(&[&new_pin_enc, &pin_hash_enc])
            } else {
                session.authenticate(&[&pin_hash_enc, &new_pin_enc])
            };
            let mut ui = Scripted::new(Answer::Confirmed);
            let response = run(
                authenticator,
                &mut ui,
                &request(&[
                    (0x01, Value::Uint(protocol as u64)),
                    (0x02, Value::Uint(0x04)),
                    (0x03, session.key_agreement()),
                    (0x04, Value::Bytes(param)),
                    (0x05, Value::Bytes(new_pin_enc)),
                    (0x06, Value::Bytes(pin_hash_enc)),
                ]),
            );
            assert_eq!(ui.asked, [], "changePIN shows no screen");
            response
        };
        // The MAC covers newPinEnc || pinHashEnc in that order.
        assert_eq!(
            change(&mut authenticator, b"1234", false),
            [PIN_AUTH_INVALID]
        );
        assert_eq!(change(&mut authenticator, b"0000", true), [PIN_INVALID]);
        assert_eq!(retries(&mut authenticator), (7, false));
        assert_eq!(change(&mut authenticator, b"1234", true), [OK]);
        assert_eq!(retries(&mut authenticator), (8, false));

        let param = hmac(&old_token, &[b"x"])[..protocol.signature_len()].to_vec();
        assert!(!authenticator.client_pin.verify_token(
            &authenticator.crypto,
            protocol,
            &[b"x"],
            &param,
            1
        ));
        let (response, _) = pin_token(&mut authenticator, &mut ui, protocol, b"1234", None, None);
        assert_eq!(response, [PIN_INVALID]);
        let (response, _) = pin_token(&mut authenticator, &mut ui, protocol, b"98765", None, None);
        assert_eq!(response[0], OK);
    }
}

/// getPinUvAuthTokenUsingUvWithPermissions with `ui` for `permissions` and `rp_id`.
fn uv_token(
    authenticator: &mut TestAuthenticator,
    ui: &mut Scripted,
    permissions: Option<u64>,
    rp_id: Option<&'static str>,
) -> (Vec<u8>, Session) {
    let session = Session::start(authenticator, Protocol::Two);
    let mut members = vec![
        (0x01, Value::Uint(2)),
        (0x02, Value::Uint(0x06)),
        (0x03, session.key_agreement()),
    ];
    if let Some(permissions) = permissions {
        members.push((0x09, Value::Uint(permissions)));
    }
    if let Some(rp_id) = rp_id {
        members.push((0x0A, Value::Text(rp_id)));
    }
    let response = run(authenticator, ui, &request(&members));
    (response, session)
}

/// Built-in UV (§6.5.5.7.3): consent naming the permissions and the RP (step 9), then the device
/// PIN on the keypad (step 10), gives a token with user presence, no client PIN needed; the token
/// is the device's.
#[test]
fn built_in_uv_gives_a_token_with_presence() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.now_ms = 1_000;
    let (response, session) =
        uv_token(&mut authenticator, &mut ui, Some(0x02), Some("example.com"));
    assert_eq!(response[0], OK);
    let token = session.decrypt(&parse_response(&response[1..]).token.expect("token"));
    assert_eq!(token, authenticator.client_pin.token(Protocol::Two)[..]);
    assert_eq!(
        ui.asked,
        [
            (
                Asked::Token {
                    permissions: 0x02,
                    rp_id: Some("example.com".into())
                },
                USER_ACTION_TIMEOUT_MS
            ),
            (Asked::Keypad, USER_ACTION_TIMEOUT_MS)
        ]
    );
    assert!(authenticator.client_pin.user_present(1_000));
    assert!(
        authenticator
            .client_pin
            .has_permission(Permissions::GET_ASSERTION)
    );
    assert!(
        !authenticator
            .client_pin
            .has_permission(Permissions::MAKE_CREDENTIAL)
    );
}

/// Built-in UV failures (§6.5.5.7.3 step 11): a wrong entry leaves no attempt, so it is
/// UV_BLOCKED; a keypad not offered is UV_BLOCKED before any screen; backing out of the keypad
/// is a failed verification with the attempt still offered, UV_INVALID; a cancel
/// KEEPALIVE_CANCEL, no entry USER_ACTION_TIMEOUT. No token results.
#[test]
fn built_in_uv_failures() {
    for (verification, status) in [
        (Verification::Invalid, UV_BLOCKED),
        (Verification::Blocked, UV_BLOCKED),
        (Verification::Rejected, UV_INVALID),
        (Verification::Cancelled, KEEPALIVE_CANCEL),
        (Verification::TimedOut, USER_ACTION_TIMEOUT),
    ] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(Answer::Confirmed);
        ui.verification = verification;
        let (response, _) = uv_token(&mut authenticator, &mut ui, Some(0x01), Some("example.com"));
        assert_eq!(response, [status], "{verification:?}");
        assert_eq!(
            ui.asked.last(),
            Some(&(Asked::Keypad, USER_ACTION_TIMEOUT_MS)),
            "{verification:?}"
        );
        assert!(!authenticator.client_pin.in_use(0), "{verification:?}");
    }

    // Consent not approved (§6.5.5.7.3 step 9) is OPERATION_DENIED and shows no keypad, so no
    // device PIN try is at stake; a cancel ends the request as for any screen.
    for (answer, status) in [
        (Answer::Rejected, OPERATION_DENIED),
        (Answer::TimedOut, OPERATION_DENIED),
        (Answer::Cancelled, KEEPALIVE_CANCEL),
    ] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(answer);
        let (response, _) = uv_token(&mut authenticator, &mut ui, Some(0x01), Some("example.com"));
        assert_eq!(response, [status], "{answer:?}");
        assert_eq!(
            ui.asked,
            [(
                Asked::Token {
                    permissions: 0x01,
                    rp_id: Some("example.com".into())
                },
                USER_ACTION_TIMEOUT_MS
            )],
            "{answer:?}"
        );
        assert!(!authenticator.client_pin.in_use(0), "{answer:?}");
    }

    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.uv_retries = 0;
    let (response, _) = uv_token(&mut authenticator, &mut ui, Some(0x01), Some("example.com"));
    assert_eq!(response, [UV_BLOCKED]);
    assert_eq!(ui.asked, [], "no keypad when no attempt is offered");
}

/// mc and ga need a permissions RP ID (CTAP 2.2 §6.5.5.7, the RP ID column "Required"): without
/// one the request misses a mandatory parameter, before any screen and without spending a try.
/// Only getPinToken's default permissions are bound by their first use.
#[test]
fn rp_scoped_permissions_need_an_rp_id() {
    let mut authenticator = authenticator();
    assert_eq!(set_pin(&mut authenticator, Protocol::Two, b"1234"), OK);
    let mut ui = Scripted::new(Answer::Confirmed);
    for permissions in [0x01, 0x02, 0x03] {
        let (response, _) = pin_token(
            &mut authenticator,
            &mut ui,
            Protocol::Two,
            b"1234",
            Some(permissions),
            None,
        );
        assert_eq!(
            response,
            [MISSING_PARAMETER],
            "client PIN, {permissions:#x}"
        );
        let (response, _) = uv_token(&mut authenticator, &mut ui, Some(permissions), None);
        assert_eq!(
            response,
            [MISSING_PARAMETER],
            "built-in UV, {permissions:#x}"
        );
    }
    assert_eq!(ui.asked, []);
    assert_eq!(retries(&mut authenticator), (8, false));
}

/// Built-in UV requires permissions (MISSING_PARAMETER), refuses 0 (INVALID_PARAMETER) and acfg
/// without uvAcfg (UNAUTHORIZED_PERMISSION), all before the keypad.
#[test]
fn built_in_uv_permission_checks() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    for (permissions, status) in [
        (None, MISSING_PARAMETER),
        (Some(0), INVALID_PARAMETER),
        (Some(0x20), UNAUTHORIZED_PERMISSION),
        (Some(0x04), UNAUTHORIZED_PERMISSION),
    ] {
        let (response, _) = uv_token(&mut authenticator, &mut ui, permissions, None);
        assert_eq!(response, [status], "{permissions:?}");
    }
    assert_eq!(ui.asked, []);
}

/// getUVRetries answers what the device offers: {5: 1} while the device count is full.
#[test]
fn get_uv_retries_reports_the_device() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x07))]),
    );
    assert_eq!(response, [0x00, 0xA1, 0x05, 0x01]);
    ui.uv_retries = 0;
    let response = run(
        &mut authenticator,
        &mut ui,
        &request(&[(0x02, Value::Uint(0x07))]),
    );
    assert_eq!(response, [0x00, 0xA1, 0x05, 0x00]);
}

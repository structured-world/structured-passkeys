//! authenticatorConfig against CTAP 2.2 §6.11: toggleAlwaysUv behind an `acfg` token.

use super::super::client_pin::tests::{Value, command, hmac, parse_response, run, uv_token};
use super::super::tests::{Scripted, TestAuthenticator, authenticator};
use super::MESSAGE_PREFIX;
use crate::ui::Answer;

const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
const MISSING_PARAMETER: u8 = 0x14;
const PIN_AUTH_INVALID: u8 = 0x33;
const PUAT_REQUIRED: u8 = 0x36;

/// The `acfg` permission bit (§6.5.5.7).
const ACFG: u64 = 0x20;
/// The `cm` permission bit.
const CM: u64 = 0x04;

/// A pinUvAuthToken from built-in user verification with `permissions`, decrypted.
fn token(authenticator: &mut TestAuthenticator, permissions: u64) -> Vec<u8> {
    let mut ui = Scripted::new(Answer::Confirmed);
    let (response, session) = uv_token(authenticator, &mut ui, Some(permissions), None);
    assert_eq!(response[0], OK, "a token");
    session.decrypt(&parse_response(&response[1..]).token.expect("a token"))
}

/// An authenticatorConfig request for `sub_command`, its pinUvAuthParam the protocol two MAC
/// under `token` over `32 × 0xff || 0x0d || subCommand`.
fn request(sub_command: u8, token: &[u8]) -> Vec<u8> {
    let param = hmac(token, &[&MESSAGE_PREFIX, &[sub_command]]);
    command(
        0x0D,
        &[
            (0x01, Value::Uint(u64::from(sub_command))),
            (0x03, Value::Uint(2)),
            (0x04, Value::Bytes(param.to_vec())),
        ],
    )
}

fn send(authenticator: &mut TestAuthenticator, request: &[u8]) -> Vec<u8> {
    run(
        authenticator,
        &mut Scripted::new(Answer::Confirmed),
        request,
    )
}

/// The alwaysUv option of getInfo (§6.4 member 0x04).
fn always_uv(authenticator: &mut TestAuthenticator) -> bool {
    let info = send(authenticator, &[0x04]);
    let key = b"\x68alwaysUv";
    let at = info
        .windows(key.len())
        .position(|window| window == key)
        .expect("alwaysUv is reported");
    match info[at + key.len()] {
        0xF5 => true,
        0xF4 => false,
        other => panic!("alwaysUv is {other:#04x}"),
    }
}

/// toggleAlwaysUv (§6.11.2) turns alwaysUv on and off again; getInfo reports each state.
#[test]
fn toggle_always_uv_switches_both_ways() {
    let mut authenticator = authenticator();
    assert!(!always_uv(&mut authenticator));
    let acfg = token(&mut authenticator, ACFG);
    assert_eq!(send(&mut authenticator, &request(0x02, &acfg)), [OK]);
    assert!(always_uv(&mut authenticator));
    let acfg = token(&mut authenticator, ACFG);
    assert_eq!(send(&mut authenticator, &request(0x02, &acfg)), [OK]);
    assert!(!always_uv(&mut authenticator));
}

/// Since user verification is always configured, step 4 always applies: no pinUvAuthParam is
/// PUAT_REQUIRED; a wrong MAC or a token without `acfg` is PIN_AUTH_INVALID; neither toggles.
#[test]
fn toggle_always_uv_needs_an_acfg_token() {
    let mut authenticator = authenticator();
    let bare = command(0x0D, &[(0x01, Value::Uint(2))]);
    assert_eq!(send(&mut authenticator, &bare), [PUAT_REQUIRED]);
    assert_eq!(
        send(&mut authenticator, &request(0x02, &[0x5A; 32])),
        [PIN_AUTH_INVALID]
    );
    let cm = token(&mut authenticator, CM);
    assert_eq!(
        send(&mut authenticator, &request(0x02, &cm)),
        [PIN_AUTH_INVALID]
    );
    assert!(!always_uv(&mut authenticator));
}

/// enableEnterpriseAttestation, setMinPINLength, vendorPrototype and unknown codes are
/// INVALID_PARAMETER (§6.11 step 2); a request without subCommand is MISSING_PARAMETER.
#[test]
fn other_subcommands_are_invalid() {
    let mut authenticator = authenticator();
    let acfg = token(&mut authenticator, ACFG);
    for sub_command in [0x01, 0x03, 0xFF, 0x07] {
        assert_eq!(
            send(&mut authenticator, &request(sub_command, &acfg)),
            [INVALID_PARAMETER],
            "subcommand {sub_command}"
        );
    }
    let none = command(0x0D, &[(0x03, Value::Uint(2))]);
    assert_eq!(send(&mut authenticator, &none), [MISSING_PARAMETER]);
}

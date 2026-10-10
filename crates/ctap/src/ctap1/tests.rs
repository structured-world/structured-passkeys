//! Parsing of CTAP1/U2F request messages against FIDO U2F Raw Message Formats v1.2 §3 to §6 and
//! the ISO/IEC 7816-4 APDU encodings. Messages are written out byte by byte.

use super::{Control, Request, StatusWord, parse};

const CHALLENGE: [u8; 32] = [0xC1; 32];
const APPLICATION: [u8; 32] = [0xA9; 32];

/// An extended-length APDU (§3): header, `00 Lc1 Lc2`, the data, and Le `00 00` when `le`.
fn extended(header: [u8; 4], data: &[u8], le: bool) -> Vec<u8> {
    let mut message = header.to_vec();
    let length = u16::try_from(data.len()).expect("short enough");
    message.push(0x00);
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(data);
    if le {
        message.extend_from_slice(&[0x00, 0x00]);
    }
    message
}

/// A short APDU: header, one-byte Lc, the data, and a one-byte Le when `le`.
fn short(header: [u8; 4], data: &[u8], le: bool) -> Vec<u8> {
    let mut message = header.to_vec();
    message.push(u8::try_from(data.len()).expect("short"));
    message.extend_from_slice(data);
    if le {
        message.push(0x00);
    }
    message
}

fn registration_data() -> Vec<u8> {
    [&CHALLENGE[..], &APPLICATION].concat()
}

fn authentication_data(key_handle: &[u8]) -> Vec<u8> {
    let length = u8::try_from(key_handle.len()).expect("short");
    [&CHALLENGE[..], &APPLICATION, &[length], key_handle].concat()
}

/// U2F_VERSION in every encoding platforms use: the header alone, a short Le alone, the
/// extended Le alone, and an extended Lc of zero followed by an extended Le (as python-fido2
/// sends it).
#[test]
fn version_in_every_encoding() {
    let header = [0x00, 0x03, 0x00, 0x00];
    let messages: [&[u8]; 4] = [
        &header,
        &[0x00, 0x03, 0x00, 0x00, 0x00],
        &[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for message in messages {
        assert_eq!(parse(message), Ok(Request::Version), "{message:02x?}");
    }
}

/// U2F_VERSION carries no data (§6.1): data is SW_WRONG_LENGTH.
#[test]
fn version_with_data_is_wrong_length() {
    assert_eq!(
        parse(&extended([0x00, 0x03, 0x00, 0x00], &[0x01], true)),
        Err(StatusWord::WrongLength)
    );
}

/// U2F_REGISTER takes the challenge, then the application parameter (§4.1), in the extended
/// encoding with or without Le and in the short one; P1 0x03, as Firefox sends it, is accepted.
#[test]
fn registration_in_every_encoding() {
    let expected = Ok(Request::Register {
        challenge: CHALLENGE,
        application: APPLICATION,
    });
    let data = registration_data();
    for message in [
        extended([0x00, 0x01, 0x00, 0x00], &data, true),
        extended([0x00, 0x01, 0x00, 0x00], &data, false),
        extended([0x00, 0x01, 0x03, 0x00], &data, true),
        short([0x00, 0x01, 0x00, 0x00], &data, false),
        short([0x00, 0x01, 0x00, 0x00], &data, true),
    ] {
        assert_eq!(parse(&message), expected, "{message:02x?}");
    }
}

/// A registration whose data is not exactly 64 bytes is SW_WRONG_LENGTH (§4.1).
#[test]
fn registration_of_the_wrong_length() {
    let data = registration_data();
    for length in [0, 63, 65] {
        let mut data = data.clone();
        data.resize(length, 0xEE);
        assert_eq!(
            parse(&extended([0x00, 0x01, 0x00, 0x00], &data, true)),
            Err(StatusWord::WrongLength),
            "{length}"
        );
    }
}

/// U2F_AUTHENTICATE takes the control byte from P1 (§5.1), then the challenge, the application
/// parameter and the length-prefixed key handle.
#[test]
fn authentication_with_each_control_byte() {
    let key_handle = [0x4B; 70];
    for (p1, control) in [
        (0x07, Control::CheckOnly),
        (0x03, Control::EnforcePresence),
        (0x08, Control::DontEnforcePresence),
    ] {
        assert_eq!(
            parse(&extended(
                [0x00, 0x02, p1, 0x00],
                &authentication_data(&key_handle),
                true
            )),
            Ok(Request::Authenticate {
                control,
                challenge: CHALLENGE,
                application: APPLICATION,
                key_handle: key_handle.to_vec(),
            }),
            "{p1:02x}"
        );
    }
}

/// A control byte §5.1 does not define is SW_WRONG_DATA.
#[test]
fn an_unknown_control_byte_is_wrong_data() {
    for p1 in [0x00, 0x01, 0x05, 0x09, 0xFF] {
        assert_eq!(
            parse(&extended(
                [0x00, 0x02, p1, 0x00],
                &authentication_data(&[0x4B; 8]),
                true
            )),
            Err(StatusWord::WrongData),
            "{p1:02x}"
        );
    }
}

/// A key handle length that does not match the bytes after it, and data too short to hold the
/// parameters, are SW_WRONG_LENGTH.
#[test]
fn authentication_of_the_wrong_length() {
    let mut longer = authentication_data(&[0x4B; 8]);
    longer.push(0x00);
    let mut shorter = authentication_data(&[0x4B; 8]);
    shorter.pop();
    let truncated = [&CHALLENGE[..], &APPLICATION].concat();
    for data in [longer, shorter, truncated, CHALLENGE.to_vec()] {
        assert_eq!(
            parse(&extended([0x00, 0x02, 0x03, 0x00], &data, true)),
            Err(StatusWord::WrongLength),
            "{} bytes",
            data.len()
        );
    }
}

/// An empty key handle parses; whether it opens is for the authentication to decide.
#[test]
fn an_empty_key_handle_parses() {
    assert!(matches!(
        parse(&extended(
            [0x00, 0x02, 0x07, 0x00],
            &authentication_data(&[]),
            true
        )),
        Ok(Request::Authenticate { key_handle, .. }) if key_handle.is_empty()
    ));
}

/// A class other than 0x00 is SW_CLA_NOT_SUPPORTED, an instruction other than the three U2F
/// ones (vendor-specific ones included, §3.2) SW_INS_NOT_SUPPORTED.
#[test]
fn other_classes_and_instructions_are_refused() {
    assert_eq!(
        parse(&[0x80, 0x03, 0x00, 0x00]),
        Err(StatusWord::ClaNotSupported)
    );
    for ins in [0x00, 0x04, 0x10, 0x40, 0xBF, 0xC0] {
        assert_eq!(
            parse(&[0x00, ins, 0x00, 0x00]),
            Err(StatusWord::InsNotSupported),
            "{ins:02x}"
        );
    }
}

/// A message shorter than its header, an Lc beyond the data, and bytes after the data that are
/// no Le are SW_WRONG_LENGTH.
#[test]
fn malformed_apdus_are_wrong_length() {
    let mut beyond = extended([0x00, 0x01, 0x00, 0x00], &registration_data(), false);
    beyond.truncate(beyond.len() - 1);
    let mut trailing = extended([0x00, 0x01, 0x00, 0x00], &registration_data(), true);
    trailing.push(0x00);
    let mut short_trailing = short([0x00, 0x01, 0x00, 0x00], &registration_data(), true);
    short_trailing.push(0x00);
    let messages: [&[u8]; 6] = [
        &[],
        &[0x00, 0x03, 0x00],
        &beyond,
        &trailing,
        &short_trailing,
        &[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for message in messages {
        assert_eq!(
            parse(message),
            Err(StatusWord::WrongLength),
            "{message:02x?}"
        );
    }
}

/// The status words of §3.3, most significant byte first.
#[test]
fn status_words_follow_the_specification() {
    let words = [
        (StatusWord::NoError, [0x90, 0x00]),
        (StatusWord::ConditionsNotSatisfied, [0x69, 0x85]),
        (StatusWord::CommandNotAllowed, [0x69, 0x86]),
        (StatusWord::WrongData, [0x6A, 0x80]),
        (StatusWord::WrongLength, [0x67, 0x00]),
        (StatusWord::ClaNotSupported, [0x6E, 0x00]),
        (StatusWord::InsNotSupported, [0x6D, 0x00]),
        (StatusWord::Unknown, [0x6F, 0x00]),
    ];
    for (word, bytes) in words {
        assert_eq!(word.to_bytes(), bytes, "{word:?}");
    }
}

//! CTAP1/U2F messages (FIDO U2F Raw Message Formats v1.2, 2017-04-11), which `CTAPHID_MSG`
//! carries (CTAP 2.2 §11.2.9.1.1): parsing a request APDU into the command it asks for, and the
//! status words that answer it. [`Authenticator::execute_ctap1`] runs a parsed command.
//!
//! A message is an ISO/IEC 7816-4 command APDU, in the extended encoding the U2F specification
//! asks for (§3) or the short one some platforms send; a response is its data followed by a
//! two-byte status word.
//!
//! [`Authenticator::execute_ctap1`]: crate::ctap2::Authenticator::execute_ctap1
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::ctap1::{Request, StatusWord, parse};
//!
//! // U2F_VERSION as an extended APDU without data (U2F raw messages §6.1).
//! assert_eq!(parse(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]), Ok(Request::Version));
//! // A class other than 0x00.
//! assert_eq!(parse(&[0x80, 0x03, 0x00, 0x00]), Err(StatusWord::ClaNotSupported));
//! ```

use alloc::vec::Vec;

/// Length of the challenge parameter, a SHA-256 of the client data (§4.1, §5.1).
pub const CHALLENGE_LEN: usize = 32;
/// Length of the application parameter, a SHA-256 of the application identity (§4.1, §5.1).
pub const APPLICATION_LEN: usize = 32;
/// The version string U2F_VERSION answers (§6.1).
pub const VERSION: &[u8] = b"U2F_V2";

/// Instruction U2F_REGISTER (§4.1).
const INS_REGISTER: u8 = 0x01;
/// Instruction U2F_AUTHENTICATE (§5.1).
const INS_AUTHENTICATE: u8 = 0x02;
/// Instruction U2F_VERSION (§6.1).
const INS_VERSION: u8 = 0x03;

/// The status words a response ends with (§3.3, ISO/IEC 7816-4 §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    /// The command completed successfully.
    NoError = 0x9000,
    /// The request was rejected due to test-of-user-presence being required, or a check-only
    /// authentication found the key handle valid.
    ConditionsNotSatisfied = 0x6985,
    /// The command is not allowed in the current state: U2F is disabled while alwaysUv is on
    /// (CTAP 2.2 §7.2.2).
    CommandNotAllowed = 0x6986,
    /// The request was rejected due to an invalid key handle or control byte.
    WrongData = 0x6A80,
    /// The length of the request was invalid.
    WrongLength = 0x6700,
    /// The class byte of the request is not supported.
    ClaNotSupported = 0x6E00,
    /// The instruction of the request is not supported.
    InsNotSupported = 0x6D00,
    /// An internal failure with no more specific status (ISO/IEC 7816-4 §5.6, "no precise
    /// diagnosis").
    Unknown = 0x6F00,
}

impl StatusWord {
    /// The two bytes that end a response, most significant first.
    pub const fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

/// The control byte of U2F_AUTHENTICATE (§5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// 0x07: only whether the key handle is valid for the application, with no signature.
    CheckOnly,
    /// 0x03: sign after test-of-user-presence.
    EnforcePresence,
    /// 0x08: sign whether or not the user is present. This authenticator asks for presence
    /// anyway: every signature is confirmed on the device.
    DontEnforcePresence,
}

impl TryFrom<u8> for Control {
    type Error = StatusWord;

    /// §5.1 defines three control bytes; another is SW_WRONG_DATA, as an invalid parameter of
    /// the request (§3.3).
    fn try_from(byte: u8) -> Result<Self, StatusWord> {
        match byte {
            0x07 => Ok(Self::CheckOnly),
            0x03 => Ok(Self::EnforcePresence),
            0x08 => Ok(Self::DontEnforcePresence),
            _ => Err(StatusWord::WrongData),
        }
    }
}

/// A parsed CTAP1/U2F request, owning what its execution needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// U2F_REGISTER (§4.1).
    Register {
        /// The challenge parameter.
        challenge: [u8; CHALLENGE_LEN],
        /// The application parameter.
        application: [u8; APPLICATION_LEN],
    },
    /// U2F_AUTHENTICATE (§5.1).
    Authenticate {
        /// The control byte.
        control: Control,
        /// The challenge parameter.
        challenge: [u8; CHALLENGE_LEN],
        /// The application parameter.
        application: [u8; APPLICATION_LEN],
        /// The key handle, the credential ID a registration returned.
        key_handle: Vec<u8>,
    },
    /// U2F_VERSION (§6.1).
    Version,
}

/// The header and the data of a command APDU in the extended encoding U2F messages use (§3:
/// `00 Lc1 Lc2` before the data, an optional two-byte Le after it) or the short one (a one-byte
/// Lc, an optional one-byte Le), which some platforms send although §3 asks for the extended
/// one. A length that does not match the message is SW_WRONG_LENGTH.
fn apdu(message: &[u8]) -> Result<([u8; 4], &[u8]), StatusWord> {
    let (header, body) = message
        .split_first_chunk::<4>()
        .ok_or(StatusWord::WrongLength)?;
    let data = match body {
        // No data and no Le, a short Le alone, or an extended Le alone (`00 Le1 Le2`, ISO/IEC
        // 7816-4 §5.1 case 2E): command data follows an extended Lc, so three bytes hold no data.
        [] | [_] | [0x00, _, _] => &[][..],
        // Extended: `00`, then Lc on two bytes, the data and an optional two-byte Le.
        [0x00, high, low, rest @ ..] => {
            let lc = usize::from(u16::from_be_bytes([*high, *low]));
            match rest.len().checked_sub(lc) {
                Some(0 | 2) => &rest[..lc],
                _ => return Err(StatusWord::WrongLength),
            }
        }
        // Short: Lc, the data and an optional one-byte Le.
        [lc, rest @ ..] => {
            let lc = usize::from(*lc);
            match rest.len().checked_sub(lc) {
                Some(0 | 1) => &rest[..lc],
                _ => return Err(StatusWord::WrongLength),
            }
        }
    };
    Ok((*header, data))
}

/// Parses a CTAP1/U2F request message into the command it asks for, or the status word that
/// refuses it. P1 of U2F_REGISTER and U2F_VERSION and P2 of every command are not checked: §4.1
/// and §6.1 give them no meaning, §3.3 defines no status word to refuse one with, and platforms
/// differ in what they send (Firefox sends P1 0x03 with a registration).
///
/// # Errors
///
/// SW_WRONG_LENGTH for a malformed APDU or data of the wrong length, SW_CLA_NOT_SUPPORTED for a
/// class other than 0x00, SW_INS_NOT_SUPPORTED for another instruction (vendor-specific ones
/// included, §3.2), SW_WRONG_DATA for an unknown control byte.
pub fn parse(message: &[u8]) -> Result<Request, StatusWord> {
    let ([cla, ins, p1, _p2], data) = apdu(message)?;
    if cla != 0x00 {
        return Err(StatusWord::ClaNotSupported);
    }
    match ins {
        INS_REGISTER => {
            let (challenge, application) = data
                .split_first_chunk::<CHALLENGE_LEN>()
                .ok_or(StatusWord::WrongLength)?;
            let application = <[u8; APPLICATION_LEN]>::try_from(application)
                .map_err(|_| StatusWord::WrongLength)?;
            Ok(Request::Register {
                challenge: *challenge,
                application,
            })
        }
        INS_AUTHENTICATE => {
            let control = Control::try_from(p1)?;
            let (challenge, rest) = data
                .split_first_chunk::<CHALLENGE_LEN>()
                .ok_or(StatusWord::WrongLength)?;
            let (application, rest) = rest
                .split_first_chunk::<APPLICATION_LEN>()
                .ok_or(StatusWord::WrongLength)?;
            let (length, key_handle) = rest.split_first().ok_or(StatusWord::WrongLength)?;
            if key_handle.len() != usize::from(*length) {
                return Err(StatusWord::WrongLength);
            }
            Ok(Request::Authenticate {
                control,
                challenge: *challenge,
                application: *application,
                key_handle: key_handle.to_vec(),
            })
        }
        INS_VERSION => {
            if !data.is_empty() {
                return Err(StatusWord::WrongLength);
            }
            Ok(Request::Version)
        }
        _ => Err(StatusWord::InsNotSupported),
    }
}

#[cfg(test)]
mod tests;

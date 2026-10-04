//! CTAP2 commands (CTAP 2.2 §6): dispatch by command code, status codes (§8.2) and
//! authenticatorGetInfo (§6.4).
//!
//! A request is the command byte followed by its CBOR parameters; a response is a status byte
//! followed, on success, by the CBOR response. A request is parsed into a [`Command`] first, which
//! owns what it needs: a command that waits for the user then runs while the transport keeps
//! receiving into the buffer the request came in.
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::ctap2::{Authenticator, MaxMsgSize, Settings, StatusCode};
//! use structured_passkeys_ctap::soft::SoftCrypto;
//! use structured_passkeys_ctap::storage::{MemoryStorage, Store};
//! use structured_passkeys_ctap::ui::{Answer, Prompt, Ui, Verification};
//!
//! /// A user who confirms everything and has no PIN to enter.
//! struct Present;
//!
//! impl Ui for Present {
//!     fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
//!         Answer::Confirmed
//!     }
//!     fn verify_user(&mut self, _timeout_ms: u32) -> Verification {
//!         Verification::Blocked
//!     }
//!     fn uv_retries(&mut self) -> u8 {
//!         0
//!     }
//!     fn now_ms(&self) -> u64 {
//!         0
//!     }
//! }
//!
//! let max_msg_size = MaxMsgSize::try_from(1024).expect("at least 1024");
//! let crypto = SoftCrypto::new([1; 32], [2; 32]);
//! let store = Store::open(MemoryStorage::new(4, 4));
//! let mut authenticator = Authenticator::new(Settings { max_msg_size }, crypto, store);
//! let mut response = [0u8; 128];
//! let length = authenticator.process(&[0x04], &mut Present, &mut response);
//! assert_eq!(response[0], StatusCode::Ok as u8);
//! assert!(length > 1);
//! ```

mod client_pin;

pub use client_pin::{ClientPinRequest, FEATURES, SubCommand};

use crate::cbor::{self, Encoder, Full};
use crate::crypto::Crypto;
use crate::pin::{ClientPin, Protocol};
use crate::storage::{Storage, Store};
use crate::ui::{Answer, Prompt, USER_ACTION_TIMEOUT_MS, Ui};

/// The AAGUID of this application, the same on every device (WebAuthn L3 §6.5.1).
pub const AAGUID: [u8; 16] = [
    0x8F, 0x92, 0x0F, 0x83, 0x9D, 0xA2, 0x48, 0x61, 0x94, 0xD7, 0x7F, 0x3C, 0x99, 0x45, 0xD5, 0x32,
];

/// CTAP2 command codes (§6, §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandCode {
    /// authenticatorMakeCredential (§6.1).
    MakeCredential = 0x01,
    /// authenticatorGetAssertion (§6.2).
    GetAssertion = 0x02,
    /// authenticatorGetInfo (§6.4).
    GetInfo = 0x04,
    /// authenticatorClientPIN (§6.5).
    ClientPin = 0x06,
    /// authenticatorReset (§6.6).
    Reset = 0x07,
    /// authenticatorGetNextAssertion (§6.3).
    GetNextAssertion = 0x08,
    /// authenticatorBioEnrollment (§6.7).
    BioEnrollment = 0x09,
    /// authenticatorCredentialManagement (§6.8).
    CredentialManagement = 0x0A,
    /// authenticatorSelection (§6.9).
    Selection = 0x0B,
    /// authenticatorLargeBlobs (§6.10).
    LargeBlobs = 0x0C,
    /// authenticatorConfig (§6.11).
    Config = 0x0D,
}

/// A command code that §6 does not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownCommand(pub u8);

impl TryFrom<u8> for CommandCode {
    type Error = UnknownCommand;

    fn try_from(code: u8) -> Result<Self, UnknownCommand> {
        Ok(match code {
            0x01 => CommandCode::MakeCredential,
            0x02 => CommandCode::GetAssertion,
            0x04 => CommandCode::GetInfo,
            0x06 => CommandCode::ClientPin,
            0x07 => CommandCode::Reset,
            0x08 => CommandCode::GetNextAssertion,
            0x09 => CommandCode::BioEnrollment,
            0x0A => CommandCode::CredentialManagement,
            0x0B => CommandCode::Selection,
            0x0C => CommandCode::LargeBlobs,
            0x0D => CommandCode::Config,
            other => return Err(UnknownCommand(other)),
        })
    }
}

/// CTAP status codes (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    /// Successful response.
    Ok = 0x00,
    /// The command is not a valid CTAP command.
    InvalidCommand = 0x01,
    /// The command included an invalid parameter.
    InvalidParameter = 0x02,
    /// Invalid message or item length.
    InvalidLength = 0x03,
    /// Invalid message sequencing.
    InvalidSeq = 0x04,
    /// Message timed out.
    Timeout = 0x05,
    /// Channel busy.
    ChannelBusy = 0x06,
    /// Command requires channel lock.
    LockRequired = 0x0A,
    /// Command not allowed on this channel.
    InvalidChannel = 0x0B,
    /// Invalid or unexpected CBOR type.
    CborUnexpectedType = 0x11,
    /// Error when parsing CBOR.
    InvalidCbor = 0x12,
    /// Missing non-optional parameter.
    MissingParameter = 0x14,
    /// Limit for number of items exceeded.
    LimitExceeded = 0x15,
    // No 0x16: CTAP2_ERR_UNSUPPORTED_EXTENSION exists only in CTAP 2.0 and is absent from the
    // §8.2 table; an extension the authenticator does not know is ignored (§8, unknown map
    // keys), never rejected.
    /// Fingerprint database is full.
    FpDatabaseFull = 0x17,
    /// Large blob storage is full.
    LargeBlobStorageFull = 0x18,
    /// Valid credential found in the exclude list.
    CredentialExcluded = 0x19,
    /// Lengthy operation in progress.
    Processing = 0x21,
    /// Credential not valid for the authenticator.
    InvalidCredential = 0x22,
    /// Waiting for user interaction.
    UserActionPending = 0x23,
    /// Lengthy operation in progress.
    OperationPending = 0x24,
    /// No request is pending.
    NoOperations = 0x25,
    /// Requested algorithm not supported.
    UnsupportedAlgorithm = 0x26,
    /// Not authorized for the requested operation.
    OperationDenied = 0x27,
    /// Internal key storage is full.
    KeyStoreFull = 0x28,
    /// Unsupported option.
    UnsupportedOption = 0x2B,
    /// Option not valid for the current operation.
    InvalidOption = 0x2C,
    /// Pending keepalive was cancelled.
    KeepaliveCancel = 0x2D,
    /// No valid credentials provided.
    NoCredentials = 0x2E,
    /// A user action timed out.
    UserActionTimeout = 0x2F,
    /// Continuation command not allowed.
    NotAllowed = 0x30,
    /// PIN invalid.
    PinInvalid = 0x31,
    /// PIN blocked.
    PinBlocked = 0x32,
    /// pinUvAuthParam verification failed.
    PinAuthInvalid = 0x33,
    /// PIN authentication blocked until power cycle.
    PinAuthBlocked = 0x34,
    /// No PIN has been set.
    PinNotSet = 0x35,
    /// A pinUvAuthToken is required.
    PuatRequired = 0x36,
    /// PIN policy violation.
    PinPolicyViolation = 0x37,
    // 0x38 is "Reserved for Future Use" in §8.2; an expired pinUvAuthToken is
    // CTAP2_ERR_PIN_AUTH_INVALID (§6.5), not a code of its own.
    /// The request is too large for the authenticator.
    RequestTooLarge = 0x39,
    /// The current operation timed out.
    ActionTimeout = 0x3A,
    /// User presence is required.
    UpRequired = 0x3B,
    /// Built-in user verification is disabled.
    UvBlocked = 0x3C,
    /// A checksum did not match.
    IntegrityFailure = 0x3D,
    /// The subcommand is invalid or not implemented.
    InvalidSubcommand = 0x3E,
    /// Built-in user verification unsuccessful.
    UvInvalid = 0x3F,
    /// The permissions parameter contains an unauthorized permission.
    UnauthorizedPermission = 0x40,
    /// Other unspecified error.
    Other = 0x7F,
}

impl From<cbor::Error> for StatusCode {
    /// §8: a message not in the canonical form is CTAP2_ERR_INVALID_CBOR; a member of the wrong
    /// type is CTAP2_ERR_CBOR_UNEXPECTED_TYPE. Nesting beyond four levels is one of the §8
    /// encoding requirements, so it is INVALID_CBOR too; LIMIT_EXCEEDED (§8.2) is for item
    /// counts.
    fn from(error: cbor::Error) -> Self {
        match error {
            cbor::Error::Malformed | cbor::Error::NotCanonical | cbor::Error::TooDeep => {
                StatusCode::InvalidCbor
            }
            cbor::Error::UnexpectedType => StatusCode::CborUnexpectedType,
        }
    }
}

/// Smallest message an authenticator must accept (§8: "authenticators MUST support messages of
/// at least 1024 bytes").
pub const MIN_MESSAGE_SIZE: u16 = 1024;

/// Largest request the transport accepts, reported as `maxMsgSize` (§6.4); never below
/// [`MIN_MESSAGE_SIZE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxMsgSize(u16);

/// A message size below [`MIN_MESSAGE_SIZE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooSmall(pub u16);

impl TryFrom<u16> for MaxMsgSize {
    type Error = TooSmall;

    fn try_from(size: u16) -> Result<Self, TooSmall> {
        Self::new(size)
    }
}

impl MaxMsgSize {
    /// The size `size`, in a `const` context too.
    ///
    /// # Errors
    ///
    /// [`TooSmall`] below [`MIN_MESSAGE_SIZE`].
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_passkeys_ctap::ctap2::{MaxMsgSize, TooSmall};
    ///
    /// const SIZE: MaxMsgSize = match MaxMsgSize::new(7609) {
    ///     Ok(size) => size,
    ///     Err(_) => panic!("at least 1024"),
    /// };
    /// assert_eq!(SIZE.get(), 7609);
    /// assert_eq!(MaxMsgSize::new(1023), Err(TooSmall(1023)));
    /// ```
    pub const fn new(size: u16) -> Result<Self, TooSmall> {
        if size >= MIN_MESSAGE_SIZE {
            Ok(Self(size))
        } else {
            Err(TooSmall(size))
        }
    }

    /// The size in bytes.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Device facts the authenticator reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Largest request the transport accepts.
    pub max_msg_size: MaxMsgSize,
}

/// A parsed request, owning everything its execution needs. Not `Clone`: a request can carry PIN
/// material, which exists once and is wiped when the request is dropped.
#[derive(Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a command is moved once, from parsing to execution; boxing it would put every \
              request on the device's 8 KiB heap instead"
)]
pub enum Command {
    /// authenticatorGetInfo (§6.4).
    GetInfo,
    /// authenticatorClientPIN (§6.5).
    ClientPin(ClientPinRequest),
    /// authenticatorReset (§6.6).
    Reset,
    /// authenticatorSelection (§6.9).
    Selection,
}

/// How long after the application opens authenticatorReset is accepted. §6.6 requires it of an
/// authenticator without a display; this one has a display and keeps the window anyway, so a
/// reset is never a request that arrives while the device sits open on a desk: the user opens
/// the application for it and confirms it on the device.
pub const RESET_WINDOW_MS: u64 = 10_000;

/// The CTAP2 command processor: the device's cryptography, its persistent state and the PIN/UV
/// auth protocol state, which lives as long as the application is open.
#[derive(Debug)]
pub struct Authenticator<C, S> {
    settings: Settings,
    crypto: C,
    store: Store<S>,
    client_pin: ClientPin,
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Creates the authenticator for a device described by `settings`, with its cryptography and
    /// its opened persistent state. Initializes the PIN/UV auth protocols as at power-up
    /// (§6.5.5.1).
    pub fn new(settings: Settings, mut crypto: C, store: Store<S>) -> Self {
        let client_pin = ClientPin::new(&mut crypto);
        Self {
            settings,
            crypto,
            store,
            client_pin,
        }
    }

    /// The persistent state.
    pub const fn store(&self) -> &Store<S> {
        &self.store
    }

    /// Processes one request (command byte and CBOR parameters) and writes the response into
    /// `response`, returning its length: [`Authenticator::parse`], then
    /// [`Authenticator::execute`].
    pub fn process<U: Ui>(&mut self, request: &[u8], ui: &mut U, response: &mut [u8]) -> usize {
        let command = self.parse(request);
        self.execute(command, ui, response)
    }

    /// Parses one request (command byte and CBOR parameters) into the command it asks for, or
    /// the status that refuses it.
    ///
    /// # Errors
    ///
    /// The CTAP status of a request that cannot run: no command byte, a command not
    /// implemented, or parameters it does not take.
    pub fn parse(&self, request: &[u8]) -> Result<Command, StatusCode> {
        // A CTAPHID_CBOR message carries at least the command byte (§11.2.9.1.2).
        let (&code, parameters) = request.split_first().ok_or(StatusCode::InvalidLength)?;
        match CommandCode::try_from(code) {
            // §6.4, §6.6 and §6.9 define no parameters.
            Ok(command @ (CommandCode::GetInfo | CommandCode::Reset | CommandCode::Selection)) => {
                if !parameters.is_empty() {
                    return Err(StatusCode::InvalidLength);
                }
                Ok(match command {
                    CommandCode::Selection => Command::Selection,
                    CommandCode::Reset => Command::Reset,
                    _ => Command::GetInfo,
                })
            }
            Ok(CommandCode::ClientPin) => {
                client_pin::parse(&self.crypto, parameters).map(Command::ClientPin)
            }
            // §8.1: a command code the authenticator does not implement is
            // CTAP1_ERR_INVALID_COMMAND.
            Ok(
                CommandCode::MakeCredential
                | CommandCode::GetAssertion
                | CommandCode::GetNextAssertion
                | CommandCode::BioEnrollment
                | CommandCode::CredentialManagement
                | CommandCode::LargeBlobs
                | CommandCode::Config,
            )
            | Err(UnknownCommand(_)) => Err(StatusCode::InvalidCommand),
        }
    }

    /// Runs a parsed request, asking `ui` when the command waits for the user, and writes the
    /// response (status byte, then the CBOR response on success) into `response`, returning its
    /// length. A response that does not fit is replaced by CTAP1_ERR_OTHER; an empty `response`
    /// gets nothing.
    pub fn execute<U: Ui>(
        &mut self,
        command: Result<Command, StatusCode>,
        ui: &mut U,
        response: &mut [u8],
    ) -> usize {
        let Some((status, body)) = response.split_first_mut() else {
            return 0;
        };
        let mut encoder = Encoder::new(body);
        let outcome = command.and_then(|command| self.run(command, ui, &mut encoder));
        let written = encoder.len();
        match outcome {
            Ok(()) => {
                *status = StatusCode::Ok as u8;
                written
                    .checked_add(1)
                    .expect("the body lies inside `response` after the status byte")
            }
            Err(code) => {
                *status = code as u8;
                1
            }
        }
    }

    fn run<U: Ui>(
        &mut self,
        command: Command,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        match command {
            Command::GetInfo => self.get_info(encoder).map_err(|Full| StatusCode::Other),
            Command::ClientPin(request) => self.client_pin(&request, ui, encoder),
            Command::Reset => self.reset(ui),
            Command::Selection => selection(ui),
        }
    }

    /// authenticatorReset (§6.6): within [`RESET_WINDOW_MS`] of the application opening, else
    /// CTAP2_ERR_NOT_ALLOWED; then the user confirms on the device (refusal
    /// CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT), and the store erases
    /// every credential, the PIN and the configuration and draws a new reset ID, which revokes
    /// the seed-recoverable credential IDs created before. The PIN/UV auth state starts over too,
    /// so no token issued before verifies.
    fn reset<U: Ui>(&mut self, ui: &mut U) -> Result<(), StatusCode> {
        if ui.now_ms() > RESET_WINDOW_MS {
            return Err(StatusCode::NotAllowed);
        }
        match ui.confirm(Prompt::Reset, USER_ACTION_TIMEOUT_MS) {
            Answer::Confirmed => {}
            Answer::Rejected => return Err(StatusCode::OperationDenied),
            Answer::Cancelled => return Err(StatusCode::KeepaliveCancel),
            Answer::TimedOut => return Err(StatusCode::UserActionTimeout),
        }
        self.store.reset(&mut self.crypto)?;
        self.client_pin.reset(&mut self.crypto);
        // §6.6 also renews the device identifier, which exists only for getInfo's encIdentifier;
        // this authenticator does not report encIdentifier, so it keeps no identifier to renew.
        Ok(())
    }

    /// authenticatorGetInfo (§6.4) with the members implemented so far. `versions` stays empty
    /// until a version's command set exists and passes its conformance tests: §6.4 requires the
    /// member but not a non-empty list, and a version string is a promise platforms act on, so
    /// an empty list is the truthful answer rather than an error for the command.
    fn get_info(&self, encoder: &mut Encoder<'_>) -> Result<(), Full> {
        encoder
            .map(4)?
            // versions (0x01), required.
            .unsigned(0x01)?
            .array(0)?
            // aaguid (0x03), required.
            .unsigned(0x03)?
            .bytes(&AAGUID)?
            // maxMsgSize (0x05).
            .unsigned(0x05)?
            .unsigned(u64::from(self.settings.max_msg_size.get()))?
            // pinUvAuthProtocols (0x06), in order of preference.
            .unsigned(0x06)?
            .array(Protocol::SUPPORTED.len())?;
        for protocol in Protocol::SUPPORTED {
            encoder.unsigned(u64::from(protocol as u8))?;
        }
        Ok(())
    }
}

/// authenticatorSelection (§6.9): user presence answers CTAP2_OK with no body, an explicit
/// refusal CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT; a request the
/// platform cancelled while it waited is CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5).
fn selection<U: Ui>(ui: &mut U) -> Result<(), StatusCode> {
    match ui.confirm(Prompt::Selection, USER_ACTION_TIMEOUT_MS) {
        Answer::Confirmed => Ok(()),
        Answer::Rejected => Err(StatusCode::OperationDenied),
        Answer::Cancelled => Err(StatusCode::KeepaliveCancel),
        Answer::TimedOut => Err(StatusCode::UserActionTimeout),
    }
}

#[cfg(test)]
mod tests;

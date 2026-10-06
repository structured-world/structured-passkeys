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
//! use structured_passkeys_ctap::ctap2::{
//!     Authenticator, Link, MaxMsgSize, Settings, StatusCode, Transports,
//! };
//! use structured_passkeys_ctap::soft::SoftCrypto;
//! use structured_passkeys_ctap::storage::{MemoryStorage, Store};
//! use structured_passkeys_ctap::credential_id::Origin;
//! use structured_passkeys_ctap::ui::{Accounts, Answer, Choice, Prompt, Registration, Ui};
//!
//! /// A user who confirms everything on an unlocked device.
//! struct Present;
//!
//! impl Ui for Present {
//!     fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
//!         Answer::Confirmed
//!     }
//!     fn register(&mut self, registration: Registration<'_>, _timeout_ms: u32) -> Choice<Origin> {
//!         Choice::Chose(registration.default_origin)
//!     }
//!     fn pick<A: Accounts>(&mut self, _rp_id: &str, _accounts: &mut A, _timeout_ms: u32) -> Choice<usize> {
//!         Choice::Chose(0)
//!     }
//!     fn device_unlocked(&mut self) -> bool {
//!         true
//!     }
//!     fn now_ms(&self) -> u64 {
//!         0
//!     }
//! }
//!
//! let max_msg_size = MaxMsgSize::try_from(1024).expect("at least 1024");
//! let crypto = SoftCrypto::new([1; 32], [2; 32]);
//! let store = Store::open(MemoryStorage::new(4, 4));
//! let settings = Settings { max_msg_size, transports: Transports::Usb };
//! let mut authenticator = Authenticator::new(settings, crypto, store);
//! let mut response = [0u8; 128];
//! let length = authenticator.process(&[0x04], Link::Usb, &mut Present, &mut response);
//! assert_eq!(response[0], StatusCode::Ok as u8);
//! assert!(length > 1);
//! ```

mod client_pin;
mod credential;
mod get_assertion;
mod make_credential;

pub use client_pin::{ClientPinRequest, FEATURES, SubCommand};
pub use credential::Options;
pub use get_assertion::{GetAssertionRequest, NEXT_ASSERTION_TIMEOUT_MS};
pub use make_credential::{MakeCredentialRequest, UserEntity};

use crate::cbor::{self, Encoder, Full};
use crate::crypto::Crypto;
use crate::pin::{ClientPin, MIN_PIN_CODE_POINTS, Protocol};
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

/// The transports a device offers, reported as getInfo `transports` (§6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transports {
    /// USB HID only.
    Usb,
    /// USB HID and NFC.
    UsbAndNfc,
}

impl Transports {
    /// The AuthenticatorTransport names (WebAuthn L3 §5.8.4) of the transports.
    const fn names(self) -> &'static [&'static str] {
        match self {
            Transports::Usb => &["usb"],
            Transports::UsbAndNfc => &["nfc", "usb"],
        }
    }
}

/// Device facts the authenticator reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Largest request a transport accepts, the same on every transport.
    pub max_msg_size: MaxMsgSize,
    /// The transports the device offers.
    pub transports: Transports,
}

/// The transport a request arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// USB HID (§11.2).
    Usb,
    /// NFC (§11.3).
    Nfc,
}

/// How long an NFC tap counts as user presence: the "NFC user presence maximum time limit" of
/// CTAP 2.2 (Terminology, "Evidence of user interaction"), two minutes.
pub const NFC_PRESENCE_MS: u64 = 120_000;

/// A selection of the FIDO applet in an NFC field, the tap that is user presence over NFC.
///
/// # Examples
///
/// ```
/// use structured_passkeys_ctap::ctap2::NfcTap;
///
/// // Two selections in the same tick of a coarse clock are still two taps.
/// let first = NfcTap { at_ms: 1_000, selection: 7 };
/// let second = NfcTap { at_ms: 1_000, selection: 8 };
/// assert_ne!(first, second);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NfcTap {
    /// When the applet was selected, on the device clock.
    pub at_ms: u64,
    /// The selection's number, which tells taps apart when the clock is too coarse to; it never
    /// repeats while the application runs.
    pub selection: u64,
}

/// A parsed request, owning everything its execution needs. Not `Clone`: a request can carry PIN
/// material, which exists once and is wiped when the request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// authenticatorMakeCredential (§6.1).
    MakeCredential(MakeCredentialRequest),
    /// authenticatorGetAssertion (§6.2).
    GetAssertion(GetAssertionRequest),
    /// authenticatorGetNextAssertion (§6.3).
    GetNextAssertion,
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
    /// The last selection of the applet in an NFC field, the tap that establishes user presence
    /// over NFC; `None` once the platform ended CTAP.
    nfc_tap: Option<NfcTap>,
    /// The selection a credential operation used up: a tap counts for one registration or
    /// assertion.
    nfc_tap_used: Option<u64>,
    /// What authenticatorGetNextAssertion continues from; any other command discards it (§6.3:
    /// a stateful command continues only the command right before it).
    next_assertions: Option<get_assertion::NextAssertions>,
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
            nfc_tap: None,
            nfc_tap_used: None,
            next_assertions: None,
        }
    }

    /// The NFC tap `tap`: the device entered a reader's field and the platform selected the FIDO
    /// applet. It establishes user presence over NFC for [`NFC_PRESENCE_MS`].
    pub const fn nfc_tap(&mut self, tap: NfcTap) {
        self.nfc_tap = Some(tap);
    }

    /// The platform deselected the applet: the tap no longer counts as presence.
    pub const fn nfc_ended(&mut self) {
        self.nfc_tap = None;
    }

    /// Whether an NFC tap still counts as user presence at `now_ms`.
    fn nfc_present(&self, now_ms: u64) -> bool {
        self.nfc_tap
            .and_then(|tap| now_ms.checked_sub(tap.at_ms))
            .is_some_and(|age_ms| age_ms <= NFC_PRESENCE_MS)
    }

    /// The persistent state.
    pub const fn store(&self) -> &Store<S> {
        &self.store
    }

    /// Processes one request (command byte and CBOR parameters) that arrived on `link` and writes
    /// the response into `response`, returning its length: [`Authenticator::parse`], then
    /// [`Authenticator::execute`].
    pub fn process<U: Ui>(
        &mut self,
        request: &[u8],
        link: Link,
        ui: &mut U,
        response: &mut [u8],
    ) -> usize {
        let command = self.parse(request);
        self.execute(command, link, ui, response)
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
            // §6.3, §6.4, §6.6 and §6.9 define no parameters.
            Ok(
                command @ (CommandCode::GetInfo
                | CommandCode::Reset
                | CommandCode::Selection
                | CommandCode::GetNextAssertion),
            ) => {
                if !parameters.is_empty() {
                    return Err(StatusCode::InvalidLength);
                }
                Ok(match command {
                    CommandCode::Selection => Command::Selection,
                    CommandCode::Reset => Command::Reset,
                    CommandCode::GetNextAssertion => Command::GetNextAssertion,
                    _ => Command::GetInfo,
                })
            }
            Ok(CommandCode::ClientPin) => {
                client_pin::parse(&self.client_pin, &self.crypto, parameters)
                    .map(Command::ClientPin)
            }
            Ok(CommandCode::MakeCredential) => {
                make_credential::parse(parameters).map(Command::MakeCredential)
            }
            Ok(CommandCode::GetAssertion) => {
                get_assertion::parse(parameters).map(Command::GetAssertion)
            }
            // §8.1: a command code the authenticator does not implement is
            // CTAP1_ERR_INVALID_COMMAND.
            Ok(
                CommandCode::BioEnrollment
                | CommandCode::CredentialManagement
                | CommandCode::LargeBlobs
                | CommandCode::Config,
            )
            | Err(UnknownCommand(_)) => Err(StatusCode::InvalidCommand),
        }
    }

    /// Runs a parsed request that arrived on `link`, asking `ui` when the command waits for the
    /// user, and writes the response (status byte, then the CBOR response on success) into
    /// `response`, returning its length. A response that does not fit is replaced by
    /// CTAP1_ERR_OTHER; an empty `response` gets nothing.
    pub fn execute<U: Ui>(
        &mut self,
        command: Result<Command, StatusCode>,
        link: Link,
        ui: &mut U,
        response: &mut [u8],
    ) -> usize {
        // §6.3: authenticatorGetNextAssertion continues only the command right before it; any
        // other request, a refused one or one with no room to answer included, ends what it
        // would continue.
        if !matches!(command, Ok(Command::GetNextAssertion)) {
            self.next_assertions = None;
        }
        let Some((status, body)) = response.split_first_mut() else {
            return 0;
        };
        let mut encoder = Encoder::new(body);
        let outcome = command.and_then(|command| self.run(command, link, ui, &mut encoder));
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
        link: Link,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        match command {
            Command::MakeCredential(request) => self.make_credential(&request, link, ui, encoder),
            Command::GetAssertion(request) => self.get_assertion(&request, link, ui, encoder),
            Command::GetNextAssertion => self.get_next_assertion(ui, encoder),
            Command::GetInfo => self.get_info(encoder).map_err(|Full| StatusCode::Other),
            Command::ClientPin(request) => self.client_pin(&request, ui, encoder),
            Command::Reset => self.reset(ui),
            Command::Selection => self.selection(link, ui),
        }
    }

    /// authenticatorSelection (§6.9): user presence answers CTAP2_OK with no body, an explicit
    /// refusal CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT; a request the
    /// platform cancelled while it waited is CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5). Over NFC
    /// the tap is the presence while it counts, so no screen is shown; the tap is not used up, as
    /// it is kept for the credential operation that follows. Once it no longer counts, the device
    /// asks on its screen as over USB.
    fn selection<U: Ui>(&self, link: Link, ui: &mut U) -> Result<(), StatusCode> {
        if link == Link::Nfc && self.nfc_present(ui.now_ms()) {
            return Ok(());
        }
        match ui.confirm(Prompt::Selection, USER_ACTION_TIMEOUT_MS) {
            Answer::Confirmed => Ok(()),
            Answer::Rejected => Err(StatusCode::OperationDenied),
            Answer::Cancelled => Err(StatusCode::KeepaliveCancel),
            Answer::TimedOut => Err(StatusCode::UserActionTimeout),
        }
    }

    /// authenticatorReset (§6.6): within [`RESET_WINDOW_MS`] of the application opening, else
    /// CTAP2_ERR_NOT_ALLOWED; then the user confirms on the device (refusal
    /// CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT, a request the platform
    /// cancelled while it waited CTAP2_ERR_KEEPALIVE_CANCEL, §11.2.9.1.5), and the store erases
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

    /// authenticatorGetInfo (§6.4) with the members implemented so far. `versions` lists a version
    /// only once its command set passes the conformance suite, since a version string is a
    /// promise platforms act on: `FIDO_2_0`, the CTAP 2.0 commands (makeCredential, getAssertion,
    /// getNextAssertion, getInfo, clientPIN, reset).
    ///
    /// Options: `rk` and `up`; `uv`, since built-in user verification is the device unlock and
    /// always present; `clientPin`, true once a client PIN is set (§6.4 option IDs); and
    /// `pinUvAuthToken`, the token commands being implemented. With clientPin comes minPINLength,
    /// which "MUST be present if the authenticator supports authenticatorClientPIN".
    fn get_info(&self, encoder: &mut Encoder<'_>) -> Result<(), Full> {
        let transports = self.settings.transports.names();
        let pin_set = self.store.config().pin.is_some();
        encoder
            .map(7)?
            // versions (0x01), required.
            .unsigned(0x01)?
            .array(1)?
            .text("FIDO_2_0")?
            // aaguid (0x03), required.
            .unsigned(0x03)?
            .bytes(&AAGUID)?
            // options (0x04), keys in canonical order: shorter first, then bytewise.
            .unsigned(0x04)?
            .map(5)?
            .text("rk")?
            .bool(true)?
            .text("up")?
            .bool(true)?
            .text("uv")?
            .bool(true)?
            .text("clientPin")?
            .bool(pin_set)?
            .text("pinUvAuthToken")?
            .bool(true)?
            // maxMsgSize (0x05).
            .unsigned(0x05)?
            .unsigned(u64::from(self.settings.max_msg_size.get()))?
            // pinUvAuthProtocols (0x06), in order of preference.
            .unsigned(0x06)?
            .array(Protocol::SUPPORTED.len())?;
        for protocol in Protocol::SUPPORTED {
            encoder.unsigned(u64::from(protocol as u8))?;
        }
        // transports (0x09): the same list on every transport, as maxMsgSize is.
        encoder.unsigned(0x09)?.array(transports.len())?;
        for name in transports {
            encoder.text(name)?;
        }
        // minPINLength (0x0D): the fixed minimum; no command here changes it.
        encoder
            .unsigned(0x0D)?
            // 4 code points, far below u64.
            .unsigned(MIN_PIN_CODE_POINTS as u64)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

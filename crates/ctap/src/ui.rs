//! The user interface the device provides: a ceremony that waits for the user. The command logic
//! asks, the platform shows its screen and answers; while it waits it keeps the transport going
//! (keepalives, CANCEL) and gives up after the timeout it was given.

use crate::credential_id::{MAX_NAME_LEN, Origin};
use crate::pin::Permissions;
use crate::storage::MAX_RP_ID_LEN;

/// The longest text a screen receives for a name, and the room an RP ID gets before it is cut:
/// names are kept to 64 bytes, and each byte is shown as at most four printable ASCII characters (a
/// byte below 0x80 outside printable ASCII, or `<`, as `<XX>`; a longer UTF-8 sequence as fewer
/// characters per byte). A screen with room for this length shows every kept byte, so names that
/// differ there never look alike.
pub const MAX_SHOWN_LEN: usize = 4 * if MAX_NAME_LEN > MAX_RP_ID_LEN {
    MAX_NAME_LEN
} else {
    MAX_RP_ID_LEN
};

/// The fingerprint after an RP ID too long to show whole: a space, `#` and the first 8 bytes of
/// the SHA-256 of the whole RP ID in hex.
pub const RP_ID_FINGERPRINT_LEN: usize = 2 + 16;

/// The longest text a screen receives for an RP ID: the whole RP ID when its shown form is at most
/// [`MAX_SHOWN_LEN`] characters, which every web RP ID is, or else the form kept for it followed by
/// the fingerprint, so RP IDs that keep the same form never look alike.
pub const MAX_SHOWN_RP_ID_LEN: usize = MAX_SHOWN_LEN + RP_ID_FINGERPRINT_LEN;

/// How long a ceremony waits without user input before the request ends with
/// CTAP2_ERR_USER_ACTION_TIMEOUT; each button press or touch restarts it. CTAP 2.2 ("User action
/// timeout", Terminology) leaves the value to the authenticator, at least 10 seconds, and calls
/// thirty seconds reasonable: long enough to read the screen, find the device and answer, short
/// enough that a request nobody answers frees the device for the next one. A wait for the user's
/// action, not for the whole ceremony: a user paging through long details or many accounts keeps
/// acting.
pub const USER_ACTION_TIMEOUT_MS: u32 = 30_000;

/// A user account as the screens show it: the names the relying party gave, as received after
/// UTF-8 validation (WebAuthn L3 §6.4.1: shown as received), and the origin of its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account<'a> {
    /// `user.name`, if the relying party gave one.
    pub name: Option<&'a str>,
    /// `user.displayName`, if the relying party gave one.
    pub display_name: Option<&'a str>,
    /// The origin of the key; `None` while the user is still choosing it.
    pub origin: Option<Origin>,
}

/// The accounts an account picker offers, read one at a time: the device's heap holds the decoded
/// credential and names of one account, never of all of them.
pub trait Accounts {
    /// How many accounts there are.
    fn count(&self) -> usize;

    /// Calls `show` with the account at `index`, below [`count`](Accounts::count), and returns
    /// what it returned; `None` when that account can no longer be read, after which the picker
    /// ends without a choice.
    fn read<R>(&mut self, index: usize, show: impl FnOnce(Account<'_>) -> R) -> Option<R>;
}

/// A discoverable credential as the settings list shows it: the RP ID the index keeps, shown as
/// [`MAX_SHOWN_RP_ID_LEN`] describes, and its account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passkey<'a> {
    /// The RP ID.
    pub rp_id: &'a str,
    /// The account and the origin of its key.
    pub account: Account<'a>,
}

/// The passkeys the settings list offers, read one at a time like [`Accounts`].
pub trait Passkeys {
    /// How many passkeys there are.
    fn count(&self) -> usize;

    /// Calls `show` with the passkey at `index`, below [`count`](Passkeys::count), and returns
    /// what it returned; `None` when that passkey can no longer be read, after which the list
    /// ends without a choice.
    fn read<R>(&mut self, index: usize, show: impl FnOnce(Passkey<'_>) -> R) -> Option<R>;
}

/// What the user is asked to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt<'a> {
    /// authenticatorSelection (§6.9): the platform asks which of the connected authenticators
    /// the user means. Also the evidence of user interaction that a zero-length
    /// `pinUvAuthParam` asks for (§6.1.2 step 1, §6.2.2 step 1), which serves the same purpose.
    Selection,
    /// authenticatorReset (§6.6): erase every credential, the PIN and the settings.
    Reset,
    /// A pinUvAuthToken with `permissions` (§6.5.5.7.1 to §6.5.5.7.3: an authenticator with a
    /// display asks for consent to the permissions), for the RP `rp_id` when the request names
    /// one, shown as [`MAX_SHOWN_RP_ID_LEN`] describes.
    Token {
        /// The permissions the token would carry.
        permissions: Permissions,
        /// The permissions RP ID, if any.
        rp_id: Option<&'a str>,
    },
    /// authenticatorGetAssertion (§6.2.2 step 11): sign in to `rp_id` with `account`.
    Assertion {
        /// The RP ID of the request.
        rp_id: &'a str,
        /// The account of the credential, its names known only for a discoverable one.
        account: Account<'a>,
    },
    /// authenticatorMakeCredential found a credential of the excludeList (§6.1.2 step 16): the
    /// device is already registered with `rp_id`. Any answer ends the request with
    /// CTAP2_ERR_CREDENTIAL_EXCLUDED; the screen is the user presence that must come first.
    Excluded {
        /// The RP ID of the request.
        rp_id: &'a str,
    },
    /// A CTAP1/U2F registration (U2F raw messages §4.1): test-of-user-presence for a new key from
    /// the recovery phrase, the only origin a U2F credential takes. The message carries no RP ID,
    /// only its hash, so `rp_id` is the label the authenticator makes of it.
    U2fRegistration {
        /// The label of the application parameter.
        rp_id: &'a str,
    },
    /// The registration a browser sends to a U2F device that holds none of the credentials of an
    /// authentication, to learn from the user's touch that the device is not registered with the
    /// site. The message names no site, so the screen names none. Any answer ends the request as
    /// the browser expects, with a throwaway registration; the screen is the user presence.
    U2fNotRegistered,
    /// Delete the discoverable credential of `account` for `rp_id`, chosen in the settings list.
    /// A device-only one cannot come back, a seed-recoverable one only through the recovery
    /// phrase on another device or after a reinstall.
    Delete {
        /// The RP ID the index keeps, shown as [`MAX_SHOWN_RP_ID_LEN`] describes.
        rp_id: &'a str,
        /// The account and the origin of its key.
        account: Account<'a>,
    },
}

/// A registration to confirm (§6.1.2 step 18): the user chooses the origin of the new key, the
/// screen starting on `default_origin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration<'a> {
    /// The RP ID of the request.
    pub rp_id: &'a str,
    /// The account the credential is for.
    pub account: Account<'a>,
    /// The origin the screen offers first.
    pub default_origin: Origin,
}

/// How a confirmation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The user confirmed: user presence.
    Confirmed,
    /// The user explicitly refused.
    Rejected,
    /// The platform cancelled the request (CTAPHID_CANCEL, or its channel was reset).
    Cancelled,
    /// Nobody answered within the timeout.
    TimedOut,
}

/// How a screen that offers several confirming options ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice<T> {
    /// The user confirmed with this option: user presence.
    Chose(T),
    /// The user explicitly refused.
    Rejected,
    /// The platform cancelled the request.
    Cancelled,
    /// The timeout passed without user input.
    TimedOut,
}

/// The device's screens and clock. Screen calls block until the user answers, the platform
/// cancels, or `timeout_ms` passes without user input: every button press or touch on the device
/// restarts it, across all the screens of one call.
pub trait Ui {
    /// Asks the user to confirm `prompt` within `timeout_ms`.
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer;

    /// Asks the user to confirm `registration` within `timeout_ms`, choosing the origin of the
    /// new key.
    fn register(&mut self, registration: Registration<'_>, timeout_ms: u32) -> Choice<Origin>;

    /// Asks the user to pick one of `accounts`, most recently created first, to sign in to
    /// `rp_id` within `timeout_ms` (§6.2.2 step 15.2.3); the choice is the account's index. An
    /// account that cannot be read ends the picker as [`Choice::Rejected`].
    fn pick<A: Accounts>(
        &mut self,
        rp_id: &str,
        accounts: &mut A,
        timeout_ms: u32,
    ) -> Choice<usize>;

    /// Shows the settings list of `passkeys`, most recently created first, from the one at
    /// `start` (the first when beyond the last), and lets the user choose one to delete within
    /// `timeout_ms`; the choice is the passkey's index. Leaving the list, or a list with no
    /// passkey once the user has seen that it is empty, is [`Choice::Rejected`]; a passkey that
    /// cannot be read ends the list the same way. No request waits behind this list.
    fn browse<P: Passkeys>(
        &mut self,
        passkeys: &mut P,
        start: usize,
        timeout_ms: u32,
    ) -> Choice<usize>;

    /// Whether the operating system holds the device PIN validated: the person entered it to
    /// unlock the device, which is the built-in user verification. The application never asks
    /// for the PIN itself.
    fn device_unlocked(&mut self) -> bool;

    /// Milliseconds since the application started, from a monotonic clock that keeps running
    /// while a screen waits. The origin matters: the application start stands for the power-up
    /// that CTAP times the reset window from (§6.6).
    fn now_ms(&self) -> u64;
}

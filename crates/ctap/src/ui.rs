//! The user interface the device provides: a ceremony that waits for the user. The command logic
//! asks, the platform shows its screen and answers; while it waits it keeps the transport going
//! (keepalives, CANCEL) and gives up after the timeout it was given.

use crate::credential_id::{MAX_NAME_LEN, Origin};
use crate::pin::Permissions;
use crate::storage::MAX_RP_ID_LEN;

/// The longest text a screen receives for a name or an RP ID: they are kept to 64 bytes, and each
/// byte is shown as at most four printable ASCII characters (a byte below 0x80 outside printable
/// ASCII, or `<`, as `<XX>`; a longer UTF-8 sequence as fewer characters per byte). A screen with
/// room for this length shows every kept byte, so names that differ there never look alike.
pub const MAX_SHOWN_LEN: usize = 4 * if MAX_NAME_LEN > MAX_RP_ID_LEN {
    MAX_NAME_LEN
} else {
    MAX_RP_ID_LEN
};

/// How long a ceremony waits for the user before the request ends with
/// CTAP2_ERR_USER_ACTION_TIMEOUT. CTAP 2.2 ("User action timeout", Terminology) leaves the value
/// to the authenticator, at least 10 seconds, and calls thirty seconds reasonable: long enough to
/// read the screen, find the device and answer, short enough that a request nobody answers frees
/// the device for the next one.
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
    /// one. The RP ID is the form kept for display, at most 64 bytes.
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
    /// Nobody answered within the timeout.
    TimedOut,
}

/// The device's screens and clock. Screen calls block until the user answers, the platform
/// cancels, or the timeout passes.
pub trait Ui {
    /// Asks the user to confirm `prompt` within `timeout_ms`.
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer;

    /// Asks the user to confirm `registration` within `timeout_ms`, choosing the origin of the
    /// new key.
    fn register(&mut self, registration: Registration<'_>, timeout_ms: u32) -> Choice<Origin>;

    /// Asks the user to pick one of `accounts`, most recently created first, to sign in to
    /// `rp_id` within `timeout_ms` (§6.2.2 step 15.2.3); the choice is the index into `accounts`.
    fn pick(&mut self, rp_id: &str, accounts: &[Account<'_>], timeout_ms: u32) -> Choice<usize>;

    /// Whether the operating system holds the device PIN validated: the person entered it to
    /// unlock the device, which is the built-in user verification. The application never asks
    /// for the PIN itself.
    fn device_unlocked(&mut self) -> bool;

    /// Milliseconds since the application started, from a monotonic clock that keeps running
    /// while a screen waits. The origin matters: the application start stands for the power-up
    /// that CTAP times the reset window from (§6.6).
    fn now_ms(&self) -> u64;
}

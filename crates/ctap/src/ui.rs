//! The user interface the device provides: a ceremony that waits for the user. The command logic
//! asks, the platform shows its screen and answers; while it waits it keeps the transport going
//! (keepalives, CANCEL) and gives up after the timeout it was given.

use crate::pin::Permissions;

/// How long a ceremony waits for the user before the request ends with
/// CTAP2_ERR_USER_ACTION_TIMEOUT. CTAP 2.2 ("User action timeout", Terminology) leaves the value
/// to the authenticator, at least 10 seconds, and calls thirty seconds reasonable: long enough to
/// read the screen, find the device and answer, short enough that a request nobody answers frees
/// the device for the next one.
pub const USER_ACTION_TIMEOUT_MS: u32 = 30_000;

/// What the user is asked to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt<'a> {
    /// authenticatorSelection (§6.9): the platform asks which of the connected authenticators
    /// the user means.
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

/// How a built-in user verification ended: the user re-entered the device PIN in the ceremony
/// and the operating system checked it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The operating system validated the PIN.
    Verified,
    /// The PIN was wrong; built-in verification is blocked until a correct entry restores the
    /// operating system's count.
    Invalid,
    /// Not offered: the operating system's count is not full, so one more wrong entry would bring
    /// the device closer to its wipe. The platform falls back to the client PIN.
    Blocked,
    /// The user backed out of the keypad.
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

    /// Asks the user to enter the device PIN within `timeout_ms` and has the operating system
    /// check it. The consent to what the PIN is for comes before, through [`Ui::confirm`], so the
    /// keypad says nothing more. Offered only while [`Ui::uv_retries`] is not zero.
    fn verify_user(&mut self, timeout_ms: u32) -> Verification;

    /// Built-in user verification attempts the device offers now (`uvRetries`, §6.5.2.3): one
    /// while the operating system's retry count is full, none otherwise, so the application
    /// spends at most one of the device's tries before a correct entry.
    fn uv_retries(&mut self) -> u8;

    /// The device's monotonic clock in milliseconds; it keeps running while a screen waits.
    fn now_ms(&self) -> u64;
}

//! The device's screens for a ceremony waiting for the user, on NBGL.
//!
//! The SDK's blocking NBGL wrappers wait in a loop that only feeds the screen, so a request
//! waiting behind them could neither be cancelled nor time out. Here the use case is started
//! directly and the wait loop takes every event itself: the screen gets its buttons and touches,
//! the FIDO interface its reports (keepalives go out, CANCEL comes in), and the ticker the
//! clock that ends the wait.

use core::ffi::c_char;
use core::sync::atomic::{AtomicU8, Ordering};

use ledger_device_sdk::io::{self, CommError, CommandOrEvent, DecodedEventType, StatusWords};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use ledger_device_sdk::sys::{
    BOLOS_TRUE, DEFAULT_PIN_RETRIES, nbgl_icon_details_t, nbgl_useCaseChoice, nbgl_useCaseKeypad,
    os_global_pin_check, os_global_pin_retries,
};
use structured_passkeys_ctap::pin::Permissions;
use structured_passkeys_ctap::ui::{Answer, Prompt, Ui, Verification};
use zeroize::Zeroize;

use crate::hid;

type Comm = io::Comm<{ io::DEFAULT_BUF_SIZE }>;

/// How a screen ended, set by its NBGL callback; [`PENDING`] while it is shown.
static OUTCOME: AtomicU8 = AtomicU8::new(PENDING);
const PENDING: u8 = 0;
const CONFIRMED: u8 = 1;
const REJECTED: u8 = 2;
const PIN_ENTERED: u8 = 3;

/// Longest device PIN: Ledger PINs have 4 to 8 digits.
const PIN_MAX_DIGITS: u8 = 8;
const PIN_MIN_DIGITS: u8 = 4;

/// Room for a composed screen text: the longest consent sentence with a 64-byte RP ID.
const TEXT_LEN: usize = 160;

/// A NUL-terminated text composed for a screen. It lives in the frame of the call that shows the
/// screen and waits for it, so it outlives the screen without taking RAM between screens, which
/// the Nano X does not have to spare. Longer text is cut at a character boundary.
struct Text([u8; TEXT_LEN]);

impl Text {
    /// The concatenation of `parts`.
    fn new(parts: &[&str]) -> Self {
        let mut bytes = [0u8; TEXT_LEN];
        let mut length = 0;
        'parts: for part in parts {
            for character in part.chars() {
                let width = character.len_utf8();
                // One byte stays for the terminating NUL.
                if length + width >= TEXT_LEN {
                    break 'parts;
                }
                character.encode_utf8(&mut bytes[length..length + width]);
                length += width;
            }
        }
        Self(bytes)
    }

    /// The C string, valid while the text lives.
    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }
}

/// What a token with `permissions` lets the platform do, for the consent screen.
fn purposes(permissions: Permissions) -> &'static str {
    let sign_in = Permissions::MAKE_CREDENTIAL.bits() | Permissions::GET_ASSERTION.bits();
    let manage = Permissions::CREDENTIAL_MANAGEMENT.bits();
    let config = Permissions::AUTHENTICATOR_CONFIG.bits();
    let bits = permissions.bits();
    match (bits & sign_in != 0, bits & manage != 0, bits & config != 0) {
        (true, false, false) => "sign in and create passkeys",
        (false, true, false) => "list and delete your passkeys",
        (false, false, true) => "change the security key's settings",
        _ => "sign in, manage passkeys and change settings",
    }
}

/// The digits entered on the keypad, from its callback until `os_global_pin_check` has read
/// them; wiped right after, and before the keypad is shown.
struct PinDigits {
    digits: core::cell::UnsafeCell<[u8; PIN_MAX_DIGITS as usize]>,
    len: AtomicU8,
}

// SAFETY: one thread; the keypad callback runs inside the wait loop, never alongside it.
unsafe impl Sync for PinDigits {}

static PIN: PinDigits = PinDigits {
    digits: core::cell::UnsafeCell::new([0; PIN_MAX_DIGITS as usize]),
    len: AtomicU8::new(0),
};

impl PinDigits {
    fn wipe(&self) {
        // SAFETY: one thread, and no callback is running while the application code runs.
        unsafe { (*self.digits.get()).zeroize() };
        self.len.store(0, Ordering::Relaxed);
    }
}

unsafe extern "C" fn choice_callback(confirm: bool) {
    OUTCOME.store(
        if confirm { CONFIRMED } else { REJECTED },
        Ordering::Relaxed,
    );
}

unsafe extern "C" fn pin_callback(digits: *const u8, len: u8) {
    let len = len.min(PIN_MAX_DIGITS);
    if !digits.is_null() {
        // SAFETY: NBGL passes `len` entered digits; the buffer holds the most a PIN has, and
        // nothing else touches it while the keypad is shown.
        unsafe {
            core::ptr::copy_nonoverlapping(digits, (*PIN.digits.get()).as_mut_ptr(), len.into());
        }
    }
    PIN.len.store(len, Ordering::Relaxed);
    OUTCOME.store(PIN_ENTERED, Ordering::Relaxed);
}

unsafe extern "C" fn back_callback() {
    OUTCOME.store(REJECTED, Ordering::Relaxed);
}

/// How the wait for a screen ended.
enum Wait {
    /// The screen's callback set this outcome.
    Answered(u8),
    /// The host cancelled the request, or it was aborted with its channel.
    Cancelled,
    /// The timeout passed.
    TimedOut,
}

/// The screens of a waiting ceremony, drawn over the home screen and replaced by it again when
/// the wait ends.
pub struct DeviceUi<'a> {
    comm: &'a mut Comm,
    home: &'a mut NbglHomeAndSettings,
    glyph: &'a NbglGlyph<'a>,
}

impl<'a> DeviceUi<'a> {
    /// The screens, drawn with `glyph` and returning to `home`.
    pub fn new(
        comm: &'a mut Comm,
        home: &'a mut NbglHomeAndSettings,
        glyph: &'a NbglGlyph<'a>,
    ) -> Self {
        Self { comm, home, glyph }
    }

    /// Takes events until the shown screen answers, the request ends or `timeout_ms` passes,
    /// with the request's keepalives saying that the user is needed meanwhile.
    fn wait(&mut self, timeout_ms: u32) -> Wait {
        hid::waiting_for_user(true);
        let mut waited_ms: u64 = 0;
        let ended = loop {
            let outcome = OUTCOME.load(Ordering::Relaxed);
            if outcome != PENDING {
                break Wait::Answered(outcome);
            }
            if hid::request_ended() {
                break Wait::Cancelled;
            }
            // The first tick can come right after the screen appeared, so `k` ticks are only
            // `k - 1` full intervals: one more tick than the timeout holds keeps the wait at
            // least that long, and at most one interval longer.
            if waited_ms > u64::from(timeout_ms) {
                break Wait::TimedOut;
            }
            match self.comm.next_command_or_event() {
                CommandOrEvent::Event(DecodedEventType::Ticker) => {
                    hid::tick();
                    waited_ms = waited_ms
                        .checked_add(hid::TICK_MS)
                        .expect("a wait of 30 seconds is far from the u64 range");
                }
                // The management channel waits until the user has answered: ISO/IEC 7816-4
                // 5.6, SW 6901 "command not accepted".
                CommandOrEvent::Command(command) => {
                    match command.reply(&[], StatusWords::CmdNotAccepted) {
                        // An empty reply cannot overflow, and one that failed to leave the
                        // device has no one to report to: the host times out.
                        Ok(()) | Err(CommError::Overflow | CommError::IoError) => {}
                    }
                }
                CommandOrEvent::Event(_) => {}
            }
        };
        // Only an answered screen leaves work after it, which the keepalives then report as
        // processing; a cancelled or timed-out request is answered at once, and a keepalive in
        // front of that answer would tell the host nothing.
        if matches!(ended, Wait::Answered(_)) {
            hid::waiting_for_user(false);
        }
        self.home.show_and_return();
        ended
    }

    fn icon(&self) -> nbgl_icon_details_t {
        self.glyph.into()
    }
}

impl Ui for DeviceUi<'_> {
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer {
        // Kept in this frame until the screen is gone.
        let composed;
        let (mut confirm, mut reject) = (c"Allow".as_ptr(), c"Don't allow".as_ptr());
        let (message, sub_message): (*const c_char, *const c_char) = match prompt {
            // authenticatorSelection carries no RP or user (CTAP 2.2 §6.9), so the screen says
            // why it names none.
            Prompt::Selection => (
                c"Allow security key access?".as_ptr(),
                c"Your browser or system is choosing a security key. If a website is involved, it is shown in the next step.".as_ptr(),
            ),
            // What a reset erases, and that passkeys from the recovery phrase are only revoked
            // while this application's data lasts: reinstalling it without restoring a backup
            // brings them back.
            Prompt::Reset => {
                (confirm, reject) = (c"Reset".as_ptr(), c"Cancel".as_ptr());
                (
                    c"Reset the security key?".as_ptr(),
                    c"Erases the passkeys kept only on this device, the security key PIN and its settings, and stops passkeys from your recovery phrase working. Those come back if the app is reinstalled without restoring its backup.".as_ptr(),
                )
            }
            // The platform asks for a pinUvAuthToken with the client PIN; the screen says what
            // the token will allow and where (CTAP 2.2 §6.5.5.7.2 step 7).
            Prompt::Token { permissions, rp_id } => {
                composed = Text::new(&[
                    "Your browser or system asks to ",
                    purposes(permissions),
                    match rp_id {
                        Some(_) => " on ",
                        None => " on any website",
                    },
                    rp_id.unwrap_or_default(),
                    ".",
                ]);
                (c"Use your security key PIN?".as_ptr(), composed.as_ptr())
            }
        };
        OUTCOME.store(PENDING, Ordering::Relaxed);
        let icon = self.icon();
        // SAFETY: the strings are NUL-terminated, static or composed in this frame, and they and
        // `icon` outlive the screen, which the wait below ends before this function returns.
        unsafe {
            nbgl_useCaseChoice(
                &icon,
                message,
                sub_message,
                confirm,
                reject,
                Some(choice_callback),
            );
        }
        match self.wait(timeout_ms) {
            Wait::Answered(CONFIRMED) => Answer::Confirmed,
            Wait::Answered(_) => Answer::Rejected,
            Wait::Cancelled => Answer::Cancelled,
            Wait::TimedOut => Answer::TimedOut,
        }
    }

    fn verify_user(&mut self, timeout_ms: u32) -> Verification {
        // The device's own count: three wrong entries wipe it. The keypad is offered only while
        // the count is full, so this application spends at most one try before a correct entry
        // at unlock restores it.
        if self.uv_retries() == 0 {
            return Verification::Blocked;
        }
        PIN.wipe();
        OUTCOME.store(PENDING, Ordering::Relaxed);
        // SAFETY: the title is a static C string; the callbacks only write the statics above, and
        // the wait below ends the keypad before this function returns.
        unsafe {
            nbgl_useCaseKeypad(
                c"Enter your device PIN".as_ptr(),
                PIN_MIN_DIGITS,
                PIN_MAX_DIGITS,
                true,
                true,
                Some(pin_callback),
                Some(back_callback),
            );
        }
        let verification = match self.wait(timeout_ms) {
            Wait::Answered(PIN_ENTERED) => {
                let len = PIN.len.load(Ordering::Relaxed);
                // SAFETY: the keypad is gone, so nothing writes the digits while the syscall
                // reads `len` of them.
                let valid = unsafe { os_global_pin_check((*PIN.digits.get()).as_mut_ptr(), len) };
                if u32::from(valid) == BOLOS_TRUE {
                    Verification::Verified
                } else {
                    Verification::Invalid
                }
            }
            Wait::Answered(_) => Verification::Rejected,
            Wait::Cancelled => Verification::Cancelled,
            Wait::TimedOut => Verification::TimedOut,
        };
        PIN.wipe();
        verification
    }

    fn uv_retries(&mut self) -> u8 {
        // Derived from the device PIN's count, not kept here, so a correct client PIN does not
        // reset it as CTAP 2.2 §6.5.2.3 has a correct PIN reset uvRetries: the client PIN proves
        // nothing about the device PIN, and offering the keypad again would let built-in UV spend
        // a second of the three tries before the device wipes itself. Built-in UV comes back when
        // a correct device PIN at unlock refills the count.
        // SAFETY: a syscall without arguments.
        let retries = unsafe { os_global_pin_retries() };
        u8::from(retries >= DEFAULT_PIN_RETRIES)
    }

    fn now_ms(&self) -> u64 {
        hid::now_ms()
    }
}

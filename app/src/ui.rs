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
    BOLOS_TRUE, nbgl_icon_details_t, nbgl_useCaseChoice, os_global_pin_is_validated,
};
use structured_passkeys_ctap::pin::Permissions;
use structured_passkeys_ctap::ui::{Answer, Prompt, Ui};

use crate::hid;

type Comm = io::Comm<{ io::DEFAULT_BUF_SIZE }>;

/// How a screen ended, set by its NBGL callback; [`PENDING`] while it is shown.
static OUTCOME: AtomicU8 = AtomicU8::new(PENDING);
const PENDING: u8 = 0;
const CONFIRMED: u8 = 1;
const REJECTED: u8 = 2;

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

/// What a token with `permissions` lets the platform do, for the consent screen: exactly the
/// requested permissions, since the consent is to them (CTAP 2.2 §6.5.5.7.2 step 7).
fn purposes(permissions: Permissions) -> &'static str {
    let bits = permissions.bits();
    let create = bits & Permissions::MAKE_CREDENTIAL.bits() != 0;
    let sign_in = bits & Permissions::GET_ASSERTION.bits() != 0;
    let others = bits & !(Permissions::MAKE_CREDENTIAL.bits() | Permissions::GET_ASSERTION.bits());
    match (create, sign_in, others) {
        (false, true, 0) => "sign in with a passkey",
        (true, false, 0) => "create a passkey",
        (true, true, 0) => "sign in and create passkeys",
        (false, false, bits) if bits == Permissions::CREDENTIAL_MANAGEMENT.bits() => {
            "list and delete your passkeys"
        }
        (false, false, bits) if bits == Permissions::AUTHENTICATOR_CONFIG.bits() => {
            "change the security key's settings"
        }
        _ => "sign in, manage passkeys and change settings",
    }
}

unsafe extern "C" fn choice_callback(confirm: bool) {
    OUTCOME.store(
        if confirm { CONFIRMED } else { REJECTED },
        Ordering::Relaxed,
    );
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
            waited_ms = waited_ms
                .checked_add(self.take_event())
                .expect("a wait of 30 seconds is far from the u64 range");
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

    /// Takes one event for the shown screen and the FIDO interface; returns the milliseconds it
    /// moved the clock.
    fn take_event(&mut self) -> u64 {
        match self.comm.next_command_or_event() {
            CommandOrEvent::Event(DecodedEventType::Ticker) => {
                hid::tick();
                hid::TICK_MS
            }
            // The management channel waits until the screen is gone: ISO/IEC 7816-4 5.6,
            // SW 6901 "command not accepted".
            CommandOrEvent::Command(command) => {
                match command.reply(&[], StatusWords::CmdNotAccepted) {
                    // An empty reply cannot overflow, and one that failed to leave the device
                    // has no one to report to: the host times out.
                    Ok(()) | Err(CommError::Overflow | CommError::IoError) => {}
                }
                0
            }
            CommandOrEvent::Event(_) => 0,
        }
    }

    fn icon(&self) -> nbgl_icon_details_t {
        self.glyph.into()
    }
}

impl Ui for DeviceUi<'_> {
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer {
        // Kept in this frame until the screen is gone.
        let composed;
        let (message, sub_message): (*const c_char, *const c_char) = match prompt {
            // authenticatorSelection carries no RP or user (CTAP 2.2 §6.9), so the screen says
            // why it names none.
            Prompt::Selection => (
                c"Allow security key access?".as_ptr(),
                c"Your browser or system is choosing a security key. If a website is involved, it is shown in the next step.".as_ptr(),
            ),
            // The platform asks for a pinUvAuthToken, with the client PIN or the device unlock;
            // the screen says what the token will allow and where (CTAP 2.2 §6.5.5.7.2 step 7,
            // §6.5.5.7.3 step 9).
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
                (c"Allow security key use?".as_ptr(), composed.as_ptr())
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
                c"Allow".as_ptr(),
                c"Don't allow".as_ptr(),
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

    fn device_unlocked(&mut self) -> bool {
        // The device PIN the person entered to unlock the device is the built-in user
        // verification; the SDK's own I/O layer asks the same to refuse requests while locked,
        // so the call needs no application flag.
        // SAFETY: a syscall without arguments.
        u32::from(unsafe { os_global_pin_is_validated() }) == BOLOS_TRUE
    }

    fn now_ms(&self) -> u64 {
        hid::now_ms()
    }
}

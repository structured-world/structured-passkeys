//! The device's screens for a ceremony waiting for the user, on NBGL.
//!
//! The SDK's blocking NBGL wrappers wait in a loop that only feeds the screen, so a request
//! waiting behind them could neither be cancelled nor time out. Here the use case is started
//! directly and the wait loop takes every event itself: the screen gets its buttons and touches,
//! the FIDO interfaces their reports and APDUs (keepalives and status updates go out, CANCEL and
//! deselection come in), and the ticker the clock that ends the wait.

use core::ffi::c_char;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::io::ApduTransport;
use ledger_device_sdk::io::{CommandOrEvent, DecodedEventType};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use ledger_device_sdk::sys::{
    BOLOS_TRUE, nbgl_icon_details_t, nbgl_useCaseChoice, os_global_pin_is_validated,
};
use structured_passkeys_ctap::ctap2::Link;
use structured_passkeys_ctap::pin::Permissions;
use structured_passkeys_ctap::ui::{Answer, Prompt, Ui};

use crate::{Comm, hid};

/// The FIDO interfaces besides HID, owned by the main loop and lent to the screen of a waiting
/// request; the HID class lives in a static, where the USB stack's callbacks reach it.
pub struct Interfaces {
    /// The FIDO applet over NFC.
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    pub nfc: crate::nfc::Nfc,
}

impl Interfaces {
    /// The interfaces of this device, created once by the main loop.
    pub fn new() -> Self {
        Self {
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            nfc: crate::nfc::Nfc::new(),
        }
    }
}

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
    /// The transport of the request the screens are for.
    link: Link,
    #[cfg_attr(
        any(target_os = "nanosplus", target_os = "nanox"),
        expect(dead_code, reason = "the Nano models have no interface besides HID")
    )]
    interfaces: &'a mut Interfaces,
}

impl<'a> DeviceUi<'a> {
    /// The screens of a request that came on `link`, drawn with `glyph` and returning to `home`.
    pub fn new(
        comm: &'a mut Comm,
        home: &'a mut NbglHomeAndSettings,
        glyph: &'a NbglGlyph<'a>,
        link: Link,
        interfaces: &'a mut Interfaces,
    ) -> Self {
        Self {
            comm,
            home,
            glyph,
            link,
            interfaces,
        }
    }

    /// Tells the request's transport that it waits for the user (`true`) or processes again.
    fn waiting_for_user(&mut self, waiting: bool) {
        match self.link {
            Link::Usb => hid::waiting_for_user(waiting),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            Link::Nfc => self.interfaces.nfc.waiting_for_user(self.comm, waiting),
            // Requests come over NFC only on the devices that have it.
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            Link::Nfc => {}
        }
    }

    /// Whether the request is gone: cancelled by the platform or aborted with its transport.
    fn request_ended(&self) -> bool {
        match self.link {
            Link::Usb => hid::request_ended(),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            Link::Nfc => self.interfaces.nfc.request_ended(),
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            Link::Nfc => true,
        }
    }

    /// Takes events until the shown screen answers, the request ends or `timeout_ms` passes,
    /// with the request's transport saying that the user is needed meanwhile.
    fn wait(&mut self, timeout_ms: u32) -> Wait {
        self.waiting_for_user(true);
        let mut waited_ms: u64 = 0;
        let ended = loop {
            let outcome = OUTCOME.load(Ordering::Relaxed);
            if outcome != PENDING {
                break Wait::Answered(outcome);
            }
            if self.request_ended() {
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
        // Only an answered screen leaves work after it, which the keepalives and status updates
        // then report as processing; a cancelled or timed-out request is answered at once, and a
        // keepalive in front of that answer would tell the host nothing.
        if matches!(ended, Wait::Answered(_)) {
            self.waiting_for_user(false);
        }
        self.home.show_and_return();
        ended
    }

    /// Takes one event for the shown screen and the FIDO interfaces; returns the milliseconds it
    /// moved the clock.
    fn take_event(&mut self) -> u64 {
        let moved = match self.comm.next_command_or_event() {
            CommandOrEvent::Event(DecodedEventType::Ticker) => {
                hid::tick();
                hid::TICK_MS
            }
            // The applet answers its polls and deselection; a new request over NFC while this
            // one waits is refused as busy.
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            CommandOrEvent::Command(command) if command.transport() == Some(ApduTransport::Nfc) => {
                self.interfaces.nfc.command(command, hid::now_ms(), true);
                0
            }
            // The management channel waits until the screen is gone.
            CommandOrEvent::Command(command) => {
                crate::management(command, true);
                0
            }
            CommandOrEvent::Event(_) => 0,
        };
        // A HID request that arrived during this event, while the screen is for a request over
        // NFC, is refused as busy; the HID transport refuses the other direction itself.
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        if matches!(self.link, Link::Nfc) {
            hid::refuse_request();
        }
        moved
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

//! The device's screens for a ceremony waiting for the user, on NBGL.
//!
//! The SDK's blocking NBGL wrappers wait in a loop that only feeds the screen, so a request
//! waiting behind them could neither be cancelled nor time out. Here the use case is started
//! directly and the wait loop takes every event itself: the screen gets its buttons and touches,
//! the FIDO interfaces their reports and APDUs (keepalives and status updates go out, CANCEL and
//! deselection come in), and the ticker the clock that ends the wait.
//!
//! Every screen is one `nbgl_useCaseChoice`, which looks the same on all five devices; a ceremony
//! that needs more than two answers (the key origin at registration, the account to sign in with)
//! is a short chain of them within one timeout.

use core::ffi::c_char;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::io::ApduTransport;
use ledger_device_sdk::io::{CommandOrEvent, DecodedEventType};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use ledger_device_sdk::sys::{
    BOLOS_TRUE, nbgl_icon_details_t, nbgl_useCaseChoice, os_global_pin_is_validated,
};
use structured_passkeys_ctap::credential_id::Origin;
use structured_passkeys_ctap::ctap2::Link;
use structured_passkeys_ctap::pin::Permissions;
use structured_passkeys_ctap::ui::{Account, Answer, Choice, Prompt, Registration, Ui};

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

/// Room for a composed screen text: the longest sentence with a 64-byte RP ID and a 64-byte name.
const TEXT_LEN: usize = 256;

/// A NUL-terminated text composed for a screen. It lives in the frame of the call that shows the
/// screen and waits for it, so it outlives the screen without taking RAM between screens, which
/// the Nano X does not have to spare. Longer text is cut.
///
/// The application's NBGL fonts hold the printable ASCII range (`first_char` to `last_char` of
/// `nbgl_font_t`); any other character is written as `?`, a visible placeholder, so two names that
/// differ in a character the font lacks never look identical.
struct Text([u8; TEXT_LEN]);

impl Text {
    /// The concatenation of `parts`, with a line break kept as one.
    fn new(parts: &[&str]) -> Self {
        let mut bytes = [0u8; TEXT_LEN];
        let mut length = 0;
        'parts: for part in parts {
            for character in part.chars() {
                // One byte stays for the terminating NUL.
                if length + 1 >= TEXT_LEN {
                    break 'parts;
                }
                bytes[length] = match character {
                    ' '..='~' | '\n' => character as u8,
                    _ => b'?',
                };
                length += 1;
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

/// The name a screen gives an account: the user name, else the display name.
fn account_name<'a>(account: &Account<'a>) -> &'a str {
    account
        .name
        .or(account.display_name)
        .unwrap_or("an unnamed account")
}

/// The key origin as a badge on a sign-in screen and as the option at registration.
const fn origin_name(origin: Origin) -> &'static str {
    match origin {
        Origin::SeedRecoverable => "Recovery phrase key",
        Origin::DeviceOnly => "This device only",
    }
}

/// What the key origin means for the user: what restores the key and what loses it.
const fn origin_meaning(origin: Origin) -> &'static str {
    match origin {
        Origin::SeedRecoverable => {
            "Restored from your recovery phrase, after an app update or on another Ledger."
        }
        Origin::DeviceOnly => {
            "An app update or uninstall deletes it, so keep a second sign-in method."
        }
    }
}

/// The other key origin.
const fn other_origin(origin: Origin) -> Origin {
    match origin {
        Origin::SeedRecoverable => Origin::DeviceOnly,
        Origin::DeviceOnly => Origin::SeedRecoverable,
    }
}

/// A number of at most five digits, written into `buffer`.
fn number(value: usize, buffer: &mut [u8; 5]) -> &str {
    let mut at = buffer.len();
    let mut rest = value;
    loop {
        at -= 1;
        // A digit, 0 to 9.
        buffer[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 || at == 0 {
            break;
        }
    }
    // ASCII digits.
    core::str::from_utf8(&buffer[at..]).unwrap_or("?")
}

unsafe extern "C" fn choice_callback(confirm: bool) {
    OUTCOME.store(
        if confirm { CONFIRMED } else { REJECTED },
        Ordering::Relaxed,
    );
}

/// The four strings of a choice screen.
struct Choices {
    message: *const c_char,
    sub_message: *const c_char,
    confirm: *const c_char,
    reject: *const c_char,
}

/// The screens of a waiting ceremony, drawn over the home screen and replaced by it again when
/// the ceremony ends.
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

    /// Starts a ceremony that may take `timeout_ms`: the returned deadline bounds every screen of
    /// the ceremony together.
    fn begin(&mut self, timeout_ms: u32) -> u64 {
        hid::now_ms()
            .checked_add(u64::from(timeout_ms))
            .expect("a u64 millisecond clock outlives the device")
    }

    /// Ends a ceremony: back to the home screen. Only an answered ceremony leaves work after it,
    /// which the keepalives and status updates then report as processing; a cancelled or
    /// timed-out request is answered at once, and a keepalive in front of that answer would tell
    /// the host nothing.
    fn end(&mut self, answered: bool) {
        if answered {
            self.waiting_for_user(false);
        }
        self.home.show_and_return();
    }

    /// Shows one choice screen, with the transport saying that the user is needed, and takes
    /// events until it is answered, the request ends or the deadline passes.
    fn choose(&mut self, choices: &Choices, deadline_ms: u64) -> Answer {
        OUTCOME.store(PENDING, Ordering::Relaxed);
        let icon = self.icon();
        // SAFETY: the strings are NUL-terminated, static or composed in the caller's frame, and
        // they and `icon` outlive the screen, which the wait below ends before the caller returns.
        unsafe {
            nbgl_useCaseChoice(
                &icon,
                choices.message,
                choices.sub_message,
                choices.confirm,
                choices.reject,
                Some(choice_callback),
            );
        }
        // Said once the screen is drawn: the status change sends a keepalive at once, and a
        // drawing after it would stretch the gap to the next one. Later screens of the ceremony
        // leave the status unchanged, which sends nothing.
        self.waiting_for_user(true);
        loop {
            match OUTCOME.load(Ordering::Relaxed) {
                PENDING => {}
                CONFIRMED => return Answer::Confirmed,
                _ => return Answer::Rejected,
            }
            if self.request_ended() {
                return Answer::Cancelled;
            }
            // The first tick can come right after the screen appeared, so the deadline is passed
            // once the clock is beyond it: the wait is at least as long as asked, and at most one
            // tick longer.
            if hid::now_ms() > deadline_ms {
                return Answer::TimedOut;
            }
            self.take_event();
        }
    }

    /// Takes one event for the shown screen and the FIDO interfaces.
    fn take_event(&mut self) {
        match self.comm.next_command_or_event() {
            CommandOrEvent::Event(DecodedEventType::Ticker) => hid::tick(),
            // The applet answers its polls and deselection; a new request over NFC while this
            // one waits is refused as busy.
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            CommandOrEvent::Command(command) if command.transport() == Some(ApduTransport::Nfc) => {
                self.interfaces.nfc.command(command, hid::now_ms(), true);
            }
            // The management channel waits until the screen is gone.
            CommandOrEvent::Command(command) => crate::management(command, true),
            CommandOrEvent::Event(_) => {}
        }
        // A HID request that arrived during this event, while the screen is for a request over
        // NFC, is refused as busy; the HID transport refuses the other direction itself.
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        if matches!(self.link, Link::Nfc) {
            hid::refuse_request();
        }
    }

    fn icon(&self) -> nbgl_icon_details_t {
        self.glyph.into()
    }
}

/// The answer of a ceremony as the choice it ended in.
const fn unanswered<T>(answer: Answer) -> Choice<T> {
    match answer {
        Answer::Cancelled => Choice::Cancelled,
        Answer::TimedOut => Choice::TimedOut,
        Answer::Confirmed | Answer::Rejected => Choice::Rejected,
    }
}

impl Ui for DeviceUi<'_> {
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer {
        // Kept in this frame until the screen is gone.
        let message;
        let sub_message;
        let choices = match prompt {
            // authenticatorSelection carries no RP or user (CTAP 2.2 §6.9), so the screen says
            // why it names none.
            Prompt::Selection => Choices {
                message: c"Allow security key access?".as_ptr(),
                sub_message: c"Your browser or system is choosing a security key. If a website is involved, it is shown in the next step.".as_ptr(),
                confirm: c"Allow".as_ptr(),
                reject: c"Don't allow".as_ptr(),
            },
            // What a reset erases, and that passkeys from the recovery phrase are only revoked
            // while this application's data lasts: reinstalling it without restoring a backup
            // brings them back.
            Prompt::Reset => Choices {
                message: c"Reset the security key?".as_ptr(),
                sub_message: c"Erases the passkeys kept only on this device, the security key PIN and its settings, and stops passkeys from your recovery phrase working. Those come back if the app is reinstalled without restoring its backup.".as_ptr(),
                confirm: c"Reset".as_ptr(),
                reject: c"Cancel".as_ptr(),
            },
            // The platform asks for a pinUvAuthToken, with the client PIN or the device unlock;
            // the screen says what the token will allow and where (CTAP 2.2 §6.5.5.7.2 step 7,
            // §6.5.5.7.3 step 9).
            Prompt::Token { permissions, rp_id } => {
                sub_message = Text::new(&[
                    "Your browser or system asks to ",
                    purposes(permissions),
                    match rp_id {
                        Some(_) => " on ",
                        None => " on any website",
                    },
                    rp_id.unwrap_or_default(),
                    ".",
                ]);
                Choices {
                    message: c"Allow security key use?".as_ptr(),
                    sub_message: sub_message.as_ptr(),
                    confirm: c"Allow".as_ptr(),
                    reject: c"Don't allow".as_ptr(),
                }
            }
            // A sign-in names the RP, the account and the origin of its key (CTAP 2.2 §6.2.2
            // step 11: an authenticator with a display shows the rpId).
            Prompt::Assertion { rp_id, account } => {
                message = Text::new(&["Sign in to ", rp_id, "?"]);
                sub_message = Text::new(&[
                    "As ",
                    account_name(&account),
                    ".\n",
                    account.origin.map_or("", origin_name),
                ]);
                Choices {
                    message: message.as_ptr(),
                    sub_message: sub_message.as_ptr(),
                    confirm: c"Sign in".as_ptr(),
                    reject: c"Don't sign in".as_ptr(),
                }
            }
            // An excluded credential is reported only after this screen (§6.1.2 step 16), and
            // either answer ends the registration.
            Prompt::Excluded { rp_id } => {
                sub_message = Text::new(&[
                    "This security key already has a passkey for ",
                    rp_id,
                    ".",
                ]);
                Choices {
                    message: c"Already registered".as_ptr(),
                    sub_message: sub_message.as_ptr(),
                    confirm: c"OK".as_ptr(),
                    reject: c"Close".as_ptr(),
                }
            }
        };
        let deadline_ms = self.begin(timeout_ms);
        let answer = self.choose(&choices, deadline_ms);
        self.end(matches!(answer, Answer::Confirmed | Answer::Rejected));
        answer
    }

    /// A registration names the RP and the account and offers the key origin, starting on the
    /// default: "Key type" turns to the other origin, whose screen confirms the switch or ends
    /// the registration.
    fn register(&mut self, registration: Registration<'_>, timeout_ms: u32) -> Choice<Origin> {
        let deadline_ms = self.begin(timeout_ms);
        let mut origin = registration.default_origin;
        let outcome = loop {
            let message = Text::new(&["Create a passkey for ", registration.rp_id, "?"]);
            let sub_message = Text::new(&[
                "For ",
                account_name(&registration.account),
                ".\n",
                origin_name(origin),
                ": ",
                origin_meaning(origin),
            ]);
            let summary = Choices {
                message: message.as_ptr(),
                sub_message: sub_message.as_ptr(),
                confirm: c"Create passkey".as_ptr(),
                reject: c"Key type".as_ptr(),
            };
            match self.choose(&summary, deadline_ms) {
                Answer::Confirmed => break Choice::Chose(origin),
                Answer::Rejected => {}
                answer => break unanswered(answer),
            }
            let other = other_origin(origin);
            let message = Text::new(&["Use ", origin_name(other), "?"]);
            let sub_message = Text::new(&[origin_meaning(other)]);
            let switch = Choices {
                message: message.as_ptr(),
                sub_message: sub_message.as_ptr(),
                confirm: c"Use this key type".as_ptr(),
                reject: c"Don't create".as_ptr(),
            };
            match self.choose(&switch, deadline_ms) {
                Answer::Confirmed => origin = other,
                answer => break unanswered(answer),
            }
        };
        self.end(matches!(outcome, Choice::Chose(_) | Choice::Rejected));
        outcome
    }

    /// The accounts, most recently created first, one screen each: "Sign in" picks it, "Other
    /// account" shows the next, and the last one's refusal ends the sign-in.
    fn pick(&mut self, rp_id: &str, accounts: &[Account<'_>], timeout_ms: u32) -> Choice<usize> {
        let deadline_ms = self.begin(timeout_ms);
        let total = accounts.len();
        let mut total_buffer = [0u8; 5];
        let total_text = number(total, &mut total_buffer);
        let mut outcome = Choice::Rejected;
        for (index, account) in accounts.iter().enumerate() {
            let mut position_buffer = [0u8; 5];
            // `index` is below `total`, a slice length, so the next one fits.
            let position = number(index + 1, &mut position_buffer);
            let last = index + 1 == total;
            let message = Text::new(&["Sign in to ", rp_id, "?"]);
            let sub_message = Text::new(&[
                "As ",
                account_name(account),
                ".\n",
                account.origin.map_or("", origin_name),
                "\nAccount ",
                position,
                " of ",
                total_text,
            ]);
            let choices = Choices {
                message: message.as_ptr(),
                sub_message: sub_message.as_ptr(),
                confirm: c"Sign in".as_ptr(),
                reject: if last {
                    c"Don't sign in".as_ptr()
                } else {
                    c"Other account".as_ptr()
                },
            };
            match self.choose(&choices, deadline_ms) {
                Answer::Confirmed => {
                    outcome = Choice::Chose(index);
                    break;
                }
                Answer::Rejected if !last => {}
                answer => {
                    outcome = unanswered(answer);
                    break;
                }
            }
        }
        self.end(matches!(outcome, Choice::Chose(_) | Choice::Rejected));
        outcome
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

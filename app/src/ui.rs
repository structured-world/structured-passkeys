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
//! is a short chain of them under one user action timeout, which every button press or touch
//! restarts. A question too long for its page (a long RP ID or
//! long names) is never cut: a Nano, which pages the details of a choice but shortens its
//! question, gets the short question with the long one moved into the details; on a touch model a
//! choice page does not scroll, so the question is asked as a paginated review instead. Each screen carries the system icon Ledger's own
//! applications use for that kind of question, and an answered registration, sign-in or reset
//! ends on the system status page, as in Ledger's Security Key.

use alloc::vec::Vec;
use core::ffi::CStr;
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::io::ApduTransport;
use ledger_device_sdk::io::{CommandOrEvent, DecodedEventType};
use ledger_device_sdk::nbgl::NbglGlyph;
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
use ledger_device_sdk::sys::{BAGL_FONT_OPEN_SANS_EXTRABOLD_11px_1bpp, nbgl_getTextNbLinesInWidth};
use ledger_device_sdk::sys::{
    BOLOS_TRUE, nbgl_icon_details_t, nbgl_useCaseChoice, nbgl_useCaseStatus,
    os_global_pin_is_validated,
};
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::sys::{
    CENTERED_INFO, FIRST_USER_TOKEN, INFO_BUTTON, LARGE_CASE_INFO, TUNE_TAP_CASUAL, nbgl_content_t,
    nbgl_content_u, nbgl_contentCenteredInfo_t, nbgl_contentInfoButton_t, nbgl_genericContents_t,
    nbgl_genericContents_t__bindgen_ty_1, nbgl_getFontLineHeight, nbgl_getTextHeightInWidth,
    nbgl_getTextMaxLenInNbLines, nbgl_useCaseGenericReview,
};
use structured_passkeys_ctap::credential_id::Origin;
use structured_passkeys_ctap::ctap2::Link;
use structured_passkeys_ctap::pin::Permissions;
use structured_passkeys_ctap::ui::{
    Account, Accounts, Answer, Choice, MAX_SHOWN_LEN, MAX_SHOWN_RP_ID_LEN, Passkeys, Prompt,
    Registration, Ui,
};

use crate::home::{Home, SettingsPage};
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

/// Set when a status page has had its time, for the main loop to show the home screen again.
static HOME_DUE: AtomicBool = AtomicBool::new(false);

/// Whether the status page that ended the last ceremony is done, so the home screen is due; the
/// main loop asks after every event.
pub fn home_due() -> bool {
    // A load and a store, as the Nano X core has no atomic swap: the page's callback runs only
    // while an event is taken, never between the two.
    let due = HOME_DUE.load(Ordering::Relaxed);
    if due {
        HOME_DUE.store(false, Ordering::Relaxed);
    }
    due
}

unsafe extern "C" fn status_ended() {
    HOME_DUE.store(true, Ordering::Relaxed);
}

/// Copies of the NBGL system glyphs (`lib_nbgl/glyphs` of Ledger's secure SDK, Apache-2.0) at
/// each device's size, built like the application's own icon. The SDK compiles its glyphs into
/// the application too, but as C data that Rust code reaches only through `extern` statics, which
/// the `ropi-rwpi` device targets do not address correctly.
mod system {
    use ledger_device_sdk::include_gif;
    use ledger_device_sdk::nbgl::NbglGlyph;

    #[cfg(any(target_os = "stax", target_os = "flex"))]
    mod size {
        use super::{NbglGlyph, include_gif};

        pub const SHIELD: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/64px/SecurityShield_64px.png",
            NBGL
        ));
        pub const BACKUP: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/64px/Shield_Backup_64px.png",
            NBGL
        ));
        pub const LOGIN: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/64px/Login_64px.png", NBGL));
        pub const ACCOUNTS: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/64px/Address_Book_64px.png", NBGL));
        pub const WARNING: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/64px/Warning_64px.png", NBGL));
        pub const NOTICE: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/64px/Important_Circle_64px.png",
            NBGL
        ));
    }

    #[cfg(target_os = "apex_p")]
    mod size {
        use super::{NbglGlyph, include_gif};

        pub const SHIELD: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/48px/SecurityShield_48px.png",
            NBGL
        ));
        pub const BACKUP: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/48px/Shield_Backup_48px.png",
            NBGL
        ));
        pub const LOGIN: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/48px/Login_48px.png", NBGL));
        pub const ACCOUNTS: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/48px/Address_Book_48px.png", NBGL));
        pub const WARNING: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/48px/Warning_48px.png", NBGL));
        pub const NOTICE: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/48px/Important_Circle_48px.png",
            NBGL
        ));
    }

    // The Nano set has no backup shield: that screen keeps the application's key.
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    mod size {
        use super::{NbglGlyph, include_gif};

        pub const SHIELD: NbglGlyph = NbglGlyph::from_include(include_gif!(
            "glyphs/nbgl/nano/SecurityShield_14px.png",
            NBGL
        ));
        pub const LOGIN: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/nano/Login_14px.png", NBGL));
        pub const ACCOUNTS: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/nano/Address_Book_14px.png", NBGL));
        pub const WARNING: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/nano/icon_warning.gif", NBGL));
        pub const NOTICE: NbglGlyph =
            NbglGlyph::from_include(include_gif!("glyphs/nbgl/nano/Alert_circle_14px.png", NBGL));
    }

    pub use size::*;
}

/// What a screen asks about, which picks its icon.
#[derive(Clone, Copy)]
enum Icon {
    /// The application's key: a passkey being created.
    App,
    /// Access to the security key: selection and a token.
    Shield,
    /// A key the recovery phrase restores.
    Backup,
    /// Signing in.
    Login,
    /// Choosing between accounts.
    Accounts,
    /// Something that is lost or erased: a device-only key, a reset.
    Warning,
    /// A registration that cannot go ahead.
    Notice,
}

/// How a ceremony ended, which decides what replaces its screens.
enum Ending {
    /// Cancelled or timed out: the request is answered at once.
    Unanswered,
    /// Answered, with work left that the transport reports as processing.
    Answered,
    /// Answered, and the status page says how.
    Reported {
        success: bool,
        message: &'static CStr,
    },
}

/// Room for a composed screen text: the longest sentence around an RP ID shown at its longest,
/// [`MAX_SHOWN_RP_ID_LEN`], or an account label at its longest, [`ACCOUNT_LABEL_LEN`], with the
/// NUL; the check below holds every screen to it, so a screen shows every character of the text it
/// is given and RP IDs or names that differ never look alike.
const TEXT_LEN: usize = 640;

/// The brackets around the user name in an account label ([`account_label`]).
const LABEL_OPEN: &str = " (";
const LABEL_CLOSE: &str = ")";
/// The longest account label: both names at their longest, with the brackets.
const ACCOUNT_LABEL_LEN: usize = 2 * MAX_SHOWN_LEN + LABEL_OPEN.len() + LABEL_CLOSE.len();

/// What a token may do, as the consent screen says it ([`purposes`]).
const PURPOSES: [&str; 6] = [
    "sign in with a passkey",
    "create a passkey",
    "sign in and create passkeys",
    "list and delete your passkeys",
    "change the security key's settings",
    "sign in, manage passkeys and change settings",
];
/// The words around the shown RP ID and names, shared by the screens and the check below.
const TOKEN_ASKS: &str = "Your browser or system asks to ";
const TOKEN_ON: &str = " on ";
const EXCLUDED_HAS: &str = "This security key already has a passkey for ";
const REGISTER_FOR: &str = "For ";
const SIGN_IN_AS: &str = "As ";
const DELETE_FOR: &str = "Delete the passkey for ";
const DELETE_OF: &str = "Of ";
const PASSKEY_FOR: &str = "Passkey for ";
const PASSKEY: &str = "\nPasskey ";
const ACCOUNT: &str = "\nAccount ";
const ACCOUNT_OF: &str = " of ";
/// Digits of an account position or count ([`number`]).
const NUMBER_LEN: usize = 5;

const _: () = {
    let mut longest_purpose = 0;
    let mut index = 0;
    while index < PURPOSES.len() {
        if PURPOSES[index].len() > longest_purpose {
            longest_purpose = PURPOSES[index].len();
        }
        index += 1;
    }
    // The token consent: what it allows, on which RP.
    assert!(
        TOKEN_ASKS.len() + longest_purpose + TOKEN_ON.len() + MAX_SHOWN_RP_ID_LEN + 1 < TEXT_LEN
    );
    // An excluded registration.
    assert!(EXCLUDED_HAS.len() + MAX_SHOWN_RP_ID_LEN + 1 < TEXT_LEN);
    // The titles: "Delete the passkey for <RP>?" is the longest.
    assert!(DELETE_FOR.len() + MAX_SHOWN_RP_ID_LEN + 1 < TEXT_LEN);
    let origins = [Origin::DeviceOnly, Origin::SeedRecoverable];
    let mut index = 0;
    while index < origins.len() {
        let name = origin_name(origins[index]).len();
        // The registration summary.
        assert!(
            REGISTER_FOR.len()
                + ACCOUNT_LABEL_LEN
                + 2
                + name
                + 2
                + origin_meaning(origins[index]).len()
                < TEXT_LEN
        );
        // The account picker, which carries the most around a name.
        assert!(
            SIGN_IN_AS.len()
                + ACCOUNT_LABEL_LEN
                + 2
                + name
                + ACCOUNT.len()
                + NUMBER_LEN
                + ACCOUNT_OF.len()
                + NUMBER_LEN
                < TEXT_LEN
        );
        // A passkey of the settings list.
        assert!(PASSKEY_FOR.len() + MAX_SHOWN_RP_ID_LEN + 1 < TEXT_LEN);
        assert!(
            ACCOUNT_LABEL_LEN
                + 2
                + name
                + PASSKEY.len()
                + NUMBER_LEN
                + ACCOUNT_OF.len()
                + NUMBER_LEN
                < TEXT_LEN
        );
        // A deletion.
        assert!(
            DELETE_OF.len()
                + ACCOUNT_LABEL_LEN
                + 2
                + name
                + 2
                + deletion_meaning(origins[index]).len()
                < TEXT_LEN
        );
        index += 1;
    }
};

/// A NUL-terminated text composed for a screen. It lives in the frame of the call that shows the
/// screen and waits for it, so it outlives the screen without taking RAM between screens, which
/// the Nano X does not have to spare. Longer text is cut, never inside a `<…>` code.
///
/// The application's NBGL fonts hold the printable ASCII range (`first_char` to `last_char` of
/// `nbgl_font_t`). Text from the relying party arrives already written in that range, any other
/// character as `<` its code point in hex `>`; the application's own text is ASCII, and a
/// character outside the range would show as `?`.
struct Text([u8; TEXT_LEN]);

impl Text {
    /// The concatenation of `parts`, with a line break kept as one.
    fn new(parts: &[&str]) -> Self {
        let mut bytes = [0u8; TEXT_LEN];
        let mut length = 0;
        let mut cut = false;
        'parts: for part in parts {
            for character in part.chars() {
                // One byte stays for the terminating NUL.
                if length + 1 >= TEXT_LEN {
                    cut = true;
                    break 'parts;
                }
                bytes[length] = match character {
                    ' '..='~' | '\n' => character as u8,
                    _ => b'?',
                };
                length += 1;
            }
        }
        // A code cut in half would read as another character: the cut moves before it.
        if cut
            && let Some(open) = bytes[..length].iter().rposition(|&byte| byte == b'<')
            && !bytes[open..length].contains(&b'>')
        {
            bytes[open..length].fill(0);
        }
        Self(bytes)
    }

    /// The C string, valid while the text lives.
    fn as_c_str(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.0).expect("the last byte of a text stays NUL")
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
        (false, true, 0) => PURPOSES[0],
        (true, false, 0) => PURPOSES[1],
        (true, true, 0) => PURPOSES[2],
        (false, false, bits) if bits == Permissions::CREDENTIAL_MANAGEMENT.bits() => PURPOSES[3],
        (false, false, bits) if bits == Permissions::AUTHENTICATOR_CONFIG.bits() => PURPOSES[4],
        _ => PURPOSES[5],
    }
}

/// The account as a screen names it, in parts to compose: the display name and, when it differs,
/// the user name in brackets, so accounts that share either one still look different; one of them
/// alone when the other is missing.
fn account_label<'a>(account: &Account<'a>) -> [&'a str; 4] {
    match (account.display_name, account.name) {
        (Some(display_name), Some(name)) if display_name != name => {
            [display_name, LABEL_OPEN, name, LABEL_CLOSE]
        }
        (Some(only), _) | (None, Some(only)) => [only, "", "", ""],
        (None, None) => ["an unnamed account", "", "", ""],
    }
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

/// What deleting a key of `origin` means for the user: whether anything brings it back.
const fn deletion_meaning(origin: Origin) -> &'static str {
    match origin {
        Origin::SeedRecoverable => {
            "Your recovery phrase brings it back on another Ledger or after a reinstall."
        }
        Origin::DeviceOnly => "Its key is erased and nothing can restore it.",
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
fn number(value: usize, buffer: &mut [u8; NUMBER_LEN]) -> &str {
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

/// What a choice screen asks: its icon, the question with the RP ID, the details under it and the
/// two answers. `title` is the question without the RP ID, which ends a paginated review on a
/// touch model and heads the pages of a long question on a Nano.
struct Choices<'a> {
    icon: Icon,
    title: &'static CStr,
    message: &'a CStr,
    sub_message: &'a CStr,
    confirm: &'static CStr,
    reject: &'static CStr,
}

/// The geometry of NBGL's pages on the touch models, from Ledger's secure SDK
/// (`lib_nbgl/include/nbgl_types.h`, `nbgl_obj.h`, `nbgl_layout.h`, `nbgl_fonts.h` and the footer
/// heights in `lib_nbgl/src/nbgl_layout.c`), which decides whether a choice fits one page.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
mod page {
    use ledger_device_sdk::sys::nbgl_font_id_e;
    #[cfg(target_os = "stax")]
    use ledger_device_sdk::sys::{
        BAGL_FONT_INTER_MEDIUM_32px, BAGL_FONT_INTER_REGULAR_24px, BAGL_FONT_INTER_SEMIBOLD_24px,
    };
    #[cfg(target_os = "flex")]
    use ledger_device_sdk::sys::{
        BAGL_FONT_INTER_MEDIUM_36px, BAGL_FONT_INTER_REGULAR_28px, BAGL_FONT_INTER_SEMIBOLD_28px,
    };
    #[cfg(target_os = "apex_p")]
    use ledger_device_sdk::sys::{
        BAGL_FONT_NANODISPLAY_SEMIBOLD_24px_1bpp, BAGL_FONT_NANOTEXT_BOLD_18px_1bpp,
        BAGL_FONT_NANOTEXT_MEDIUM_18px_1bpp,
    };

    #[cfg(target_os = "stax")]
    mod model {
        use super::*;
        pub const WIDTH: u16 = 400;
        pub const HEIGHT: u16 = 672;
        pub const BORDER_MARGIN: u16 = 24;
        /// `ROUNDED_AND_FOOTER_FOOTER_HEIGHT`: the confirm button and the reject footer.
        pub const CHOICE_FOOTER: u16 = 192;
        /// `SIMPLE_FOOTER_HEIGHT`: the reject text and the page navigation of a review.
        pub const REVIEW_FOOTER: u16 = 92;
        pub const ICON_TITLE_MARGIN: u16 = 24;
        pub const TITLE_DESC_MARGIN: u16 = 16;
        /// `LARGE_MEDIUM_FONT`, the question.
        pub const TITLE_FONT: nbgl_font_id_e = BAGL_FONT_INTER_MEDIUM_32px;
        /// `SMALL_REGULAR_FONT`, the details.
        pub const TEXT_FONT: nbgl_font_id_e = BAGL_FONT_INTER_REGULAR_24px;
        /// `FOOTER_TEXT_AND_NAV_WIDTH`: the reject text left of a review's page navigation.
        pub const FOOTER_TEXT_WIDTH: u16 = 160;
        /// `SMALL_BOLD_FONT`, the reject text of a review.
        pub const FOOTER_FONT: nbgl_font_id_e = BAGL_FONT_INTER_SEMIBOLD_24px;
    }

    #[cfg(target_os = "flex")]
    mod model {
        use super::*;
        pub const WIDTH: u16 = 480;
        pub const HEIGHT: u16 = 600;
        pub const BORDER_MARGIN: u16 = 32;
        pub const CHOICE_FOOTER: u16 = 208;
        pub const REVIEW_FOOTER: u16 = 96;
        pub const ICON_TITLE_MARGIN: u16 = 24;
        pub const TITLE_DESC_MARGIN: u16 = 16;
        pub const TITLE_FONT: nbgl_font_id_e = BAGL_FONT_INTER_MEDIUM_36px;
        pub const TEXT_FONT: nbgl_font_id_e = BAGL_FONT_INTER_REGULAR_28px;
        pub const FOOTER_TEXT_WIDTH: u16 = 192;
        pub const FOOTER_FONT: nbgl_font_id_e = BAGL_FONT_INTER_SEMIBOLD_28px;
    }

    #[cfg(target_os = "apex_p")]
    mod model {
        use super::*;
        pub const WIDTH: u16 = 300;
        pub const HEIGHT: u16 = 400;
        pub const BORDER_MARGIN: u16 = 16;
        pub const CHOICE_FOOTER: u16 = 128;
        pub const REVIEW_FOOTER: u16 = 60;
        pub const ICON_TITLE_MARGIN: u16 = 16;
        pub const TITLE_DESC_MARGIN: u16 = 12;
        pub const TITLE_FONT: nbgl_font_id_e = BAGL_FONT_NANODISPLAY_SEMIBOLD_24px_1bpp;
        pub const TEXT_FONT: nbgl_font_id_e = BAGL_FONT_NANOTEXT_MEDIUM_18px_1bpp;
        pub const FOOTER_TEXT_WIDTH: u16 = 120;
        pub const FOOTER_FONT: nbgl_font_id_e = BAGL_FONT_NANOTEXT_BOLD_18px_1bpp;
    }

    pub use model::*;

    /// `AVAILABLE_WIDTH`: the width of a text.
    pub const TEXT_WIDTH: u16 = WIDTH - 2 * BORDER_MARGIN;
    /// The height a choice page gives its icon and texts: everything above its buttons. Its
    /// header is empty and only centres the content, which may use that space, as the reset
    /// screen does on the Flex.
    pub const CHOICE_HEIGHT: u16 = HEIGHT - CHOICE_FOOTER;
    /// The height a review page gives its text: above its footer, with `VERTICAL_BORDER_MARGIN`
    /// (24 on every touch model) above and below.
    pub const REVIEW_HEIGHT: u16 = HEIGHT - REVIEW_FOOTER - 2 * 24;
}

/// Whether a Nano shows `message` whole as the first page of a choice. The Nano choice shows the
/// message beside its icon on the first page and repeats it, reduced to one line, above every page
/// of the details, which it pages in full (`displayChoicePage` in
/// `lib_nbgl/src/nbgl_use_case_nanos.c`); a message longer than the first page would lose its
/// middle. Two bold lines of the step width (`AVAILABLE_WIDTH`, 128 - 2 * 7) fit beside the icon.
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
fn fits_nano_header(message: &CStr) -> bool {
    // SAFETY: the string is NUL-terminated and outlives the call, which only reads it.
    let lines = unsafe {
        nbgl_getTextNbLinesInWidth(
            BAGL_FONT_OPEN_SANS_EXTRABOLD_11px_1bpp,
            message.as_ptr(),
            128 - 2 * 7,
            true,
        )
    };
    lines <= 2
}

/// `first`, a blank line and `second` as one C string.
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
fn joined(first: &CStr, second: &CStr) -> Vec<u8> {
    let mut text = Vec::with_capacity(first.count_bytes() + 2 + second.count_bytes() + 1);
    text.extend_from_slice(first.to_bytes());
    text.extend_from_slice(b"\n\n");
    text.extend_from_slice(second.to_bytes_with_nul());
    text
}

/// The token of the confirming button that ends a paginated review.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
const CONFIRM_TOKEN: u8 = FIRST_USER_TOKEN as u8;

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
unsafe extern "C" fn review_action(token: c_int, _index: u8, _page: c_int) {
    if token == c_int::from(CONFIRM_TOKEN) {
        OUTCOME.store(CONFIRMED, Ordering::Relaxed);
    }
}

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
unsafe extern "C" fn review_rejected() {
    OUTCOME.store(REJECTED, Ordering::Relaxed);
}

/// Whether `choices` with `icon` fits one choice page, measured as NBGL lays it out
/// (`addContentCenter` in `lib_nbgl/src/nbgl_layout.c`): the icon, the question in the title font,
/// the details in the text font and the margins between them. A choice page does not scroll, so
/// text beyond this height would slide under its buttons or off the screen.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
fn fits_one_page(icon: &nbgl_icon_details_t, choices: &Choices<'_>) -> bool {
    // SAFETY: both strings are NUL-terminated and outlive the calls, which only read them.
    let (title, text) = unsafe {
        (
            nbgl_getTextHeightInWidth(
                page::TITLE_FONT,
                choices.message.as_ptr(),
                page::TEXT_WIDTH,
                true,
            ),
            nbgl_getTextHeightInWidth(
                page::TEXT_FONT,
                choices.sub_message.as_ptr(),
                page::TEXT_WIDTH,
                true,
            ),
        )
    };
    let height = u32::from(icon.height)
        + u32::from(page::ICON_TITLE_MARGIN)
        + u32::from(title)
        + u32::from(page::TITLE_DESC_MARGIN)
        + u32::from(text);
    height <= u32::from(page::CHOICE_HEIGHT)
}

/// The question and the details of `choices` cut into review pages that each fit the screen,
/// NUL-separated, every character shown: nothing is cut off, and a page break moves before a
/// `<…>` code, never into it.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
fn review_pages(choices: &Choices<'_>) -> Vec<u8> {
    let mut text = Vec::with_capacity(
        choices.message.count_bytes() + 2 + choices.sub_message.count_bytes() + 1,
    );
    text.extend_from_slice(choices.message.to_bytes());
    text.extend_from_slice(b"\n\n");
    text.extend_from_slice(choices.sub_message.to_bytes_with_nul());
    // SAFETY: a font query without pointers.
    let line_height = u16::from(unsafe { nbgl_getFontLineHeight(page::TEXT_FONT) }).max(1);
    let lines = (page::REVIEW_HEIGHT / line_height).max(1);
    let mut pages = Vec::with_capacity(text.len() + 8);
    let mut rest = &text[..];
    while rest.first().is_some_and(|&byte| byte != 0) {
        let mut fitting = 0u16;
        // SAFETY: `rest` is NUL-terminated, the end of `text`; the call writes only `fitting`.
        unsafe {
            nbgl_getTextMaxLenInNbLines(
                page::TEXT_FONT,
                rest.as_ptr().cast(),
                page::TEXT_WIDTH,
                lines,
                &mut fitting,
                true,
            );
        }
        // Without its NUL; at least one byte, so the pages always move on.
        let available = rest.len() - 1;
        let mut take = usize::from(fitting).clamp(1, available);
        if take < available
            && let Some(open) = rest[..take].iter().rposition(|&byte| byte == b'<')
            && !rest[open..take].contains(&b'>')
            && open > 0
        {
            take = open;
        }
        pages.extend_from_slice(&rest[..take]);
        pages.push(0);
        rest = &rest[take..];
        // A page starts with its text, not with the line break that ended the last one.
        while rest.first() == Some(&b'\n') {
            rest = &rest[1..];
        }
    }
    pages
}

/// `reject` with its lines broken at spaces to fit the text left of a review's page navigation:
/// that text area breaks a line wherever it runs out of width, inside a word too, since
/// `nbgl_layoutAddExtendedFooter` (`FOOTER_TEXT_AND_NAV`) leaves its `wrapping` unset.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
fn footer_text(reject: &CStr) -> Vec<u8> {
    let mut text = Vec::with_capacity(reject.count_bytes() + 1);
    let mut rest = reject.to_bytes_with_nul();
    while rest.first().is_some_and(|&byte| byte != 0) {
        let mut fitting = 0u16;
        // SAFETY: `rest` is NUL-terminated, the end of `reject`; the call writes only `fitting`.
        unsafe {
            nbgl_getTextMaxLenInNbLines(
                page::FOOTER_FONT,
                rest.as_ptr().cast(),
                page::FOOTER_TEXT_WIDTH,
                1,
                &mut fitting,
                true,
            );
        }
        // Without its NUL; at least one byte, so the lines always move on.
        let available = rest.len() - 1;
        let take = usize::from(fitting).clamp(1, available);
        let line = &rest[..take];
        let end = line
            .iter()
            .rposition(|&byte| byte != b' ')
            .map_or(0, |last| last + 1);
        if !text.is_empty() {
            text.push(b'\n');
        }
        text.extend_from_slice(&line[..end]);
        rest = &rest[take..];
        while rest.first() == Some(&b' ') {
            rest = &rest[1..];
        }
    }
    text.push(0);
    text
}

/// The screens of a waiting ceremony, drawn over the home screen and replaced by it again when
/// the ceremony ends.
pub struct DeviceUi<'a> {
    comm: &'a mut Comm,
    home: &'a mut Home,
    glyph: &'a NbglGlyph<'a>,
    /// The transport of the request the screens are for; `None` for the settings, which no
    /// request waits behind.
    link: Option<Link>,
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
        home: &'a mut Home,
        glyph: &'a NbglGlyph<'a>,
        link: Link,
        interfaces: &'a mut Interfaces,
    ) -> Self {
        Self {
            comm,
            home,
            glyph,
            link: Some(link),
            interfaces,
        }
    }

    /// The screens the settings open, drawn with `glyph` and returning to the settings of
    /// `home`. A request that arrives meanwhile is refused as busy.
    pub fn settings(
        comm: &'a mut Comm,
        home: &'a mut Home,
        glyph: &'a NbglGlyph<'a>,
        interfaces: &'a mut Interfaces,
    ) -> Self {
        Self {
            comm,
            home,
            glyph,
            link: None,
            interfaces,
        }
    }

    /// Tells the request's transport that it waits for the user (`true`) or processes again.
    fn waiting_for_user(&mut self, waiting: bool) {
        match self.link {
            Some(Link::Usb) => hid::waiting_for_user(waiting),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            Some(Link::Nfc) => self.interfaces.nfc.waiting_for_user(self.comm, waiting),
            // Requests come over NFC only on the devices that have it.
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            Some(Link::Nfc) => {}
            None => {}
        }
    }

    /// Whether the request is gone: cancelled by the platform or aborted with its transport. The
    /// settings have no request, which never ends them.
    fn request_ended(&self) -> bool {
        match self.link {
            Some(Link::Usb) => hid::request_ended(),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            Some(Link::Nfc) => self.interfaces.nfc.request_ended(),
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            Some(Link::Nfc) => true,
            None => false,
        }
    }

    /// Starts a ceremony whose screens wait `timeout_ms` for user input: the returned deadline
    /// spans every screen of the ceremony and restarts with each button press or touch.
    fn begin(&mut self, timeout_ms: u32) -> Deadline {
        Deadline::new(timeout_ms)
    }

    /// Ends a ceremony with the home screen or a status page, which the main loop replaces with
    /// the home screen when its time is up. Only an answered ceremony leaves work after it, which
    /// the keepalives and status updates then report as processing; a cancelled or timed-out
    /// request is answered at once, and a keepalive in front of that answer would tell the host
    /// nothing. The status change follows the drawing, as in [`Self::choose`].
    fn end(&mut self, ending: Ending) {
        match ending {
            Ending::Unanswered | Ending::Answered if self.link.is_none() => {
                self.home.show_settings(SettingsPage::Passkeys);
            }
            Ending::Unanswered | Ending::Answered => self.home.show_and_return(),
            Ending::Reported { success, message } => {
                // A status page replaced before its time never calls back; a flag left by one
                // that did must not end this one early.
                HOME_DUE.store(false, Ordering::Relaxed);
                // SAFETY: the message is a static NUL-terminated string; the page starts its own
                // timer and returns at once.
                unsafe { nbgl_useCaseStatus(message.as_ptr(), success, Some(status_ended)) };
            }
        }
        if !matches!(ending, Ending::Unanswered) {
            self.waiting_for_user(false);
        }
    }

    /// Shows one choice screen, with the transport saying that the user is needed, and takes
    /// events until it is answered, the request ends or the deadline passes. On a touch model a
    /// choice whose text does not fit one page becomes a paginated review of the same question.
    fn choose(&mut self, choices: &Choices<'_>, deadline: &mut Deadline) -> Answer {
        OUTCOME.store(PENDING, Ordering::Relaxed);
        let icon: nbgl_icon_details_t = match choices.icon {
            Icon::App => self.glyph.into(),
            Icon::Shield => (&system::SHIELD).into(),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            Icon::Backup => (&system::BACKUP).into(),
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            Icon::Backup => self.glyph.into(),
            Icon::Login => (&system::LOGIN).into(),
            Icon::Accounts => (&system::ACCOUNTS).into(),
            Icon::Warning => (&system::WARNING).into(),
            Icon::Notice => (&system::NOTICE).into(),
        };
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        if !fits_one_page(&icon, choices) {
            return self.review(&icon, choices, deadline);
        }
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        let (message, sub_message) = (choices.message, choices.sub_message);
        // A long question moves into the details, which a Nano pages whole, under the short one.
        #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
        let details;
        #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
        let (message, sub_message) = if fits_nano_header(choices.message) {
            (choices.message, choices.sub_message)
        } else {
            details = joined(choices.message, choices.sub_message);
            (
                choices.title,
                CStr::from_bytes_until_nul(&details).expect("joined ends with a NUL"),
            )
        };
        // SAFETY: the strings are NUL-terminated, static or composed in this or the caller's
        // frame, and they and `icon` outlive the screen, which the wait below ends before the
        // caller returns.
        unsafe {
            nbgl_useCaseChoice(
                &icon,
                message.as_ptr(),
                sub_message.as_ptr(),
                choices.confirm.as_ptr(),
                choices.reject.as_ptr(),
                Some(choice_callback),
            );
        }
        self.wait(deadline)
    }

    /// Asks the question of `choices` as a review: pages with its whole text, then a last page
    /// with the icon, the question without the RP ID and the confirming button; the reject answer
    /// stays at the foot of every page.
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    fn review(
        &mut self,
        icon: &nbgl_icon_details_t,
        choices: &Choices<'_>,
        deadline: &mut Deadline,
    ) -> Answer {
        let pages = review_pages(choices);
        let mut contents: Vec<nbgl_content_t> = pages
            .split_inclusive(|&byte| byte == 0)
            .map(|page| nbgl_content_t {
                type_: CENTERED_INFO,
                content: nbgl_content_u {
                    centeredInfo: nbgl_contentCenteredInfo_t {
                        text2: page.as_ptr().cast(),
                        style: LARGE_CASE_INFO,
                        ..Default::default()
                    },
                },
                contentActionCallback: None,
            })
            .collect();
        contents.push(nbgl_content_t {
            type_: INFO_BUTTON,
            content: nbgl_content_u {
                infoButton: nbgl_contentInfoButton_t {
                    text: choices.title.as_ptr(),
                    icon,
                    buttonText: choices.confirm.as_ptr(),
                    buttonToken: CONFIRM_TOKEN,
                    tuneId: TUNE_TAP_CASUAL,
                },
            },
            contentActionCallback: Some(review_action),
        });
        let generic = nbgl_genericContents_t {
            callbackCallNeeded: false,
            __bindgen_anon_1: nbgl_genericContents_t__bindgen_ty_1 {
                contentsList: contents.as_ptr(),
            },
            nbContents: u8::try_from(contents.len()).expect(
                "a page holds several lines of the two texts of at most TEXT_LEN bytes, far \
                 fewer than 255 pages",
            ),
        };
        let reject = footer_text(choices.reject);
        // SAFETY: the contents, their texts, `reject` and `icon` live in this frame or in the
        // caller's until the wait below ends the review; NBGL copies `generic` itself.
        unsafe {
            nbgl_useCaseGenericReview(&generic, reject.as_ptr().cast(), Some(review_rejected));
        }
        self.wait(deadline)
    }

    /// Takes events for the screen just drawn until it is answered, the request ends or the
    /// deadline passes.
    fn wait(&mut self, deadline: &mut Deadline) -> Answer {
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
            if deadline.passed() {
                return Answer::TimedOut;
            }
            self.take_event(deadline);
        }
    }

    /// Takes one event for the shown screen and the FIDO interfaces; a button press or touch
    /// restarts `deadline`.
    fn take_event(&mut self, deadline: &mut Deadline) {
        match self.comm.next_command_or_event() {
            CommandOrEvent::Event(DecodedEventType::Ticker) => hid::tick(),
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            CommandOrEvent::Event(DecodedEventType::Button(_)) => deadline.restart(),
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            CommandOrEvent::Event(DecodedEventType::Touch) => deadline.restart(),
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
        // NFC or for the settings, is refused as busy; the HID transport refuses the other
        // direction itself.
        if self.link != Some(Link::Usb) {
            hid::refuse_request();
        }
    }
}

/// The user action timeout of a ceremony (CTAP 2.2, "User action timeout"): its screens wait
/// for the user, and the request ends once `timeout_ms` pass without a button press or touch.
/// A user paging through long details or many accounts keeps it waiting; only physical input
/// restarts it, never the host.
struct Deadline {
    timeout_ms: u64,
    at_ms: u64,
}

impl Deadline {
    fn new(timeout_ms: u32) -> Self {
        let timeout_ms = u64::from(timeout_ms);
        Self {
            timeout_ms,
            at_ms: Self::after(timeout_ms),
        }
    }

    fn after(timeout_ms: u64) -> u64 {
        hid::now_ms()
            .checked_add(timeout_ms)
            .expect("a u64 millisecond clock outlives the device")
    }

    /// Gives the user the whole timeout again, from now.
    fn restart(&mut self) {
        self.at_ms = Self::after(self.timeout_ms);
    }

    /// Whether the timeout has passed. The first tick can come right after a screen appeared, so
    /// the deadline is passed once the clock is beyond it: the wait is at least as long as asked,
    /// and at most one tick longer.
    fn passed(&self) -> bool {
        hid::now_ms() > self.at_ms
    }
}

/// The status page of an answered sign-in. It names the answer, not the result: the signature is
/// made after the page appears.
const fn signed_in(confirmed: bool) -> Ending {
    if confirmed {
        Ending::Reported {
            success: true,
            message: c"Sign-in confirmed",
        }
    } else {
        Ending::Reported {
            success: false,
            message: c"Sign-in cancelled",
        }
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
                icon: Icon::Shield,
                title: c"Allow security key access?",
                message: c"Allow security key access?",
                sub_message: c"Your browser or system is choosing a security key. If a website is involved, it is shown in the next step.",
                confirm: c"Allow",
                reject: c"Don't allow",
            },
            // What a reset erases, and that passkeys from the recovery phrase are only revoked
            // while this application's data lasts: reinstalling it without restoring a backup
            // brings them back.
            Prompt::Reset => Choices {
                icon: Icon::Warning,
                title: c"Reset the security key?",
                message: c"Reset the security key?",
                sub_message: c"Erases this device's passkeys, the PIN and settings, and stops your recovery phrase passkeys. Reinstalling the app without its backup brings those back.",
                confirm: c"Reset",
                reject: c"Cancel",
            },
            // The platform asks for a pinUvAuthToken, with the client PIN or the device unlock;
            // the screen says what the token will allow and where (CTAP 2.2 §6.5.5.7.2 step 7,
            // §6.5.5.7.3 step 9).
            Prompt::Token { permissions, rp_id } => {
                sub_message = Text::new(&[
                    TOKEN_ASKS,
                    purposes(permissions),
                    match rp_id {
                        Some(_) => TOKEN_ON,
                        None => " on any website",
                    },
                    rp_id.unwrap_or_default(),
                    ".",
                ]);
                Choices {
                    icon: Icon::Shield,
                    title: c"Allow security key use?",
                    message: c"Allow security key use?",
                    sub_message: sub_message.as_c_str(),
                    confirm: c"Allow",
                    reject: c"Don't allow",
                }
            }
            // A sign-in names the RP, the account and the origin of its key (CTAP 2.2 §6.2.2
            // step 11: an authenticator with a display shows the rpId).
            Prompt::Assertion { rp_id, account } => {
                message = Text::new(&["Sign in to ", rp_id, "?"]);
                let label = account_label(&account);
                sub_message = Text::new(&[
                    SIGN_IN_AS,
                    label[0],
                    label[1],
                    label[2],
                    label[3],
                    ".\n",
                    account.origin.map_or("", origin_name),
                ]);
                Choices {
                    icon: Icon::Login,
                    title: c"Sign in?",
                    message: message.as_c_str(),
                    sub_message: sub_message.as_c_str(),
                    confirm: c"Sign in",
                    reject: c"Don't sign in",
                }
            }
            // An excluded credential is reported only after this screen (§6.1.2 step 16), and
            // either answer ends the registration.
            Prompt::Excluded { rp_id } => {
                sub_message = Text::new(&[EXCLUDED_HAS, rp_id, "."]);
                Choices {
                    icon: Icon::Notice,
                    title: c"Already registered",
                    message: c"Already registered",
                    sub_message: sub_message.as_c_str(),
                    confirm: c"OK",
                    reject: c"Close",
                }
            }
            // A deletion names the RP, the account and what becomes of its key.
            Prompt::Delete { rp_id, account } => {
                message = Text::new(&[DELETE_FOR, rp_id, "?"]);
                let label = account_label(&account);
                let (origin, meaning) = account
                    .origin
                    .map_or(("", ""), |origin| (origin_name(origin), deletion_meaning(origin)));
                sub_message = Text::new(&[
                    DELETE_OF,
                    label[0],
                    label[1],
                    label[2],
                    label[3],
                    ".\n",
                    origin,
                    if meaning.is_empty() { "" } else { ": " },
                    meaning,
                ]);
                Choices {
                    icon: Icon::Warning,
                    title: c"Delete this passkey?",
                    message: message.as_c_str(),
                    sub_message: sub_message.as_c_str(),
                    confirm: c"Delete",
                    reject: c"Keep",
                }
            }
        };
        let mut deadline = self.begin(timeout_ms);
        let answer = self.choose(&choices, &mut deadline);
        let ending = match (answer, prompt) {
            (Answer::Cancelled | Answer::TimedOut, _) => Ending::Unanswered,
            (answer, Prompt::Assertion { .. }) => signed_in(answer == Answer::Confirmed),
            (Answer::Confirmed, Prompt::Reset) => Ending::Reported {
                success: true,
                message: c"Security key reset",
            },
            (Answer::Rejected, Prompt::Reset) => Ending::Reported {
                success: false,
                message: c"Reset cancelled",
            },
            (Answer::Confirmed, Prompt::Delete { .. }) => Ending::Reported {
                success: true,
                message: c"Deletion confirmed",
            },
            (Answer::Rejected, Prompt::Delete { .. }) => Ending::Reported {
                success: false,
                message: c"Passkey kept",
            },
            // A selection or a token is followed by the request it prepares, and an excluded
            // registration has said all there is.
            _ => Ending::Answered,
        };
        self.end(ending);
        answer
    }

    /// A registration names the RP and the account and offers the key origin, starting on the
    /// default: "Key type" turns to the other origin, whose screen confirms the switch or ends
    /// the registration.
    fn register(&mut self, registration: Registration<'_>, timeout_ms: u32) -> Choice<Origin> {
        let mut deadline = self.begin(timeout_ms);
        let mut origin = registration.default_origin;
        let outcome = loop {
            let message = Text::new(&["Create a passkey for ", registration.rp_id, "?"]);
            let label = account_label(&registration.account);
            let sub_message = Text::new(&[
                REGISTER_FOR,
                label[0],
                label[1],
                label[2],
                label[3],
                ".\n",
                origin_name(origin),
                ": ",
                origin_meaning(origin),
            ]);
            let summary = Choices {
                icon: Icon::App,
                title: c"Create a passkey?",
                message: message.as_c_str(),
                sub_message: sub_message.as_c_str(),
                confirm: c"Create passkey",
                reject: c"Key type",
            };
            match self.choose(&summary, &mut deadline) {
                Answer::Confirmed => break Choice::Chose(origin),
                Answer::Rejected => {}
                answer => break unanswered(answer),
            }
            let other = other_origin(origin);
            let message = Text::new(&["Use ", origin_name(other), "?"]);
            let sub_message = Text::new(&[origin_meaning(other)]);
            let switch = Choices {
                // What the key type keeps or loses, as Ledger warns before keys stored only on
                // the device.
                icon: match other {
                    Origin::SeedRecoverable => Icon::Backup,
                    Origin::DeviceOnly => Icon::Warning,
                },
                title: c"Use this key type?",
                message: message.as_c_str(),
                sub_message: sub_message.as_c_str(),
                confirm: c"Use this key type",
                reject: c"Don't create",
            };
            match self.choose(&switch, &mut deadline) {
                Answer::Confirmed => origin = other,
                answer => break unanswered(answer),
            }
        };
        self.end(match outcome {
            Choice::Chose(_) => Ending::Reported {
                success: true,
                message: c"Registration confirmed",
            },
            Choice::Rejected => Ending::Reported {
                success: false,
                message: c"Registration cancelled",
            },
            Choice::Cancelled | Choice::TimedOut => Ending::Unanswered,
        });
        outcome
    }

    /// The accounts, most recently created first, one screen each: "Sign in" picks it, "Other
    /// account" shows the next, and the last one's refusal ends the sign-in.
    fn pick<A: Accounts>(
        &mut self,
        rp_id: &str,
        accounts: &mut A,
        timeout_ms: u32,
    ) -> Choice<usize> {
        let mut deadline = self.begin(timeout_ms);
        let total = accounts.count();
        let mut total_buffer = [0u8; NUMBER_LEN];
        let total_text = number(total, &mut total_buffer);
        let mut outcome = Choice::Rejected;
        for index in 0..total {
            let mut position_buffer = [0u8; NUMBER_LEN];
            // `index` is below `total`, a count of index entries, so the next one fits.
            let position = number(index + 1, &mut position_buffer);
            let last = index + 1 == total;
            let message = Text::new(&["Sign in to ", rp_id, "?"]);
            // The account's names live only while its screen is composed.
            let Some(sub_message) = accounts.read(index, |account| {
                let label = account_label(&account);
                Text::new(&[
                    SIGN_IN_AS,
                    label[0],
                    label[1],
                    label[2],
                    label[3],
                    ".\n",
                    account.origin.map_or("", origin_name),
                    ACCOUNT,
                    position,
                    ACCOUNT_OF,
                    total_text,
                ])
            }) else {
                break;
            };
            let choices = Choices {
                icon: Icon::Accounts,
                title: c"Sign in with this account?",
                message: message.as_c_str(),
                sub_message: sub_message.as_c_str(),
                confirm: c"Sign in",
                reject: if last {
                    c"Don't sign in"
                } else {
                    c"Other account"
                },
            };
            match self.choose(&choices, &mut deadline) {
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
        self.end(match outcome {
            Choice::Chose(_) => signed_in(true),
            Choice::Rejected => signed_in(false),
            Choice::Cancelled | Choice::TimedOut => Ending::Unanswered,
        });
        outcome
    }

    /// The passkeys, most recently created first, one screen each from the one at `start`:
    /// "Delete" picks it for the deletion screen, "Next" shows the next, and the last one's "Done"
    /// leaves the list. An empty list says so.
    fn browse<P: Passkeys>(
        &mut self,
        passkeys: &mut P,
        start: usize,
        timeout_ms: u32,
    ) -> Choice<usize> {
        let mut deadline = self.begin(timeout_ms);
        let total = passkeys.count();
        if total == 0 {
            let empty = Choices {
                icon: Icon::Notice,
                title: c"No passkeys",
                message: c"No passkeys",
                sub_message:
                    c"This security key keeps no passkey that signs in without a username yet.",
                confirm: c"OK",
                reject: c"Close",
            };
            let answer = self.choose(&empty, &mut deadline);
            self.end(Ending::Unanswered);
            return unanswered(answer);
        }
        let mut total_buffer = [0u8; NUMBER_LEN];
        let total_text = number(total, &mut total_buffer);
        let mut outcome = Choice::Rejected;
        for index in start.min(total - 1)..total {
            let mut position_buffer = [0u8; NUMBER_LEN];
            // `index` is below `total`, a count of index entries, so the next one fits.
            let position = number(index + 1, &mut position_buffer);
            let last = index + 1 == total;
            // The passkey's texts live only while its screen is composed.
            let Some((message, sub_message)) = passkeys.read(index, |passkey| {
                let label = account_label(&passkey.account);
                (
                    Text::new(&[PASSKEY_FOR, passkey.rp_id]),
                    Text::new(&[
                        label[0],
                        label[1],
                        label[2],
                        label[3],
                        ".\n",
                        passkey.account.origin.map_or("", origin_name),
                        PASSKEY,
                        position,
                        ACCOUNT_OF,
                        total_text,
                    ]),
                )
            }) else {
                break;
            };
            let choices = Choices {
                icon: Icon::Accounts,
                title: c"Passkey",
                message: message.as_c_str(),
                sub_message: sub_message.as_c_str(),
                confirm: c"Delete",
                reject: if last { c"Done" } else { c"Next" },
            };
            match self.choose(&choices, &mut deadline) {
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
        // A chosen passkey goes on to its deletion screen, which ends on its own page.
        if !matches!(outcome, Choice::Chose(_)) {
            self.end(Ending::Unanswered);
        }
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

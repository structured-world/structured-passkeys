//! The home screen and its settings: the `alwaysUv` switch and the entry to the passkey list.
//!
//! The SDK's home builder keeps its switches in an NVM array of its own, while `alwaysUv` lives in
//! the authenticator's configuration, so the use case is started here directly. A touch or a
//! button press in the settings only records what was asked; the main loop does it between events
//! and shows the settings again.

use core::ffi::{CStr, c_char, c_int};
use core::sync::atomic::{AtomicU8, Ordering};

use ledger_device_sdk::nbgl::NbglGlyph;
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::sys::TUNE_TAP_CASUAL;
use ledger_device_sdk::sys::{
    BARS_LIST, FIRST_USER_TOKEN, INIT_HOME_PAGE, OFF_STATE, ON_STATE, SWITCHES_LIST,
    nbgl_content_t, nbgl_content_u, nbgl_contentBarsList_t, nbgl_contentInfoList_t,
    nbgl_contentSwitch_t, nbgl_genericContents_t, nbgl_genericContents_t__bindgen_ty_1,
    nbgl_icon_details_t, nbgl_pageSwitchesList_s, nbgl_useCaseHomeAndSettings,
};

/// What the user asked for in the settings, for the main loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// Turn `alwaysUv` on or off.
    ToggleAlwaysUv,
    /// Open the passkey list.
    Passkeys,
}

/// The pages of the settings, one per content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SettingsPage {
    /// The entry to the passkey list.
    Passkeys = 0,
    /// The `alwaysUv` switch.
    AlwaysUv = 1,
}

/// The token of the `alwaysUv` switch and of the passkey list entry.
const ALWAYS_UV_TOKEN: u8 = FIRST_USER_TOKEN as u8;
const PASSKEYS_TOKEN: u8 = FIRST_USER_TOKEN as u8 + 1;

/// What the settings asked for and the main loop has not done yet; [`NOTHING`] when nothing.
static ASKED: AtomicU8 = AtomicU8::new(NOTHING);
const NOTHING: u8 = 0;

/// What the settings asked for since the last call, taken once.
pub fn take_asked() -> Option<Asked> {
    // A load and a store, as the Nano X core has no atomic swap: the settings callback runs only
    // while an event is taken, never between the two.
    let asked = ASKED.load(Ordering::Relaxed);
    ASKED.store(NOTHING, Ordering::Relaxed);
    match asked {
        ALWAYS_UV_TOKEN => Some(Asked::ToggleAlwaysUv),
        PASSKEYS_TOKEN => Some(Asked::Passkeys),
        _ => None,
    }
}

unsafe extern "C" fn settings_callback(token: c_int, _index: u8, _page: c_int) {
    if let Ok(token @ (ALWAYS_UV_TOKEN | PASSKEYS_TOKEN)) = u8::try_from(token) {
        ASKED.store(token, Ordering::Relaxed);
    }
}

unsafe extern "C" fn quit() {
    ledger_device_sdk::exit_app(0);
}

/// The name on the home screen and the title of the settings; the same as
/// `package.metadata.ledger.name`.
const APP_NAME: &CStr = c"Structured Passkeys";

/// What the home screen of the touch devices says under the name; without it NBGL shows its
/// default line about signing transactions on a network. The Nano home screen shows the name
/// alone, and a tagline would take its place there.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
const TAGLINE: &CStr = c"Passkeys and FIDO2 security key for signing in to websites and apps";

const VERSION: &CStr =
    match CStr::from_bytes_with_nul(concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes()) {
        Ok(version) => version,
        Err(_) => panic!("a package version has no NUL"),
    };
const DEVELOPER: &CStr =
    match CStr::from_bytes_with_nul(concat!(env!("CARGO_PKG_AUTHORS"), "\0").as_bytes()) {
        Ok(developer) => developer,
        Err(_) => panic!("package authors have no NUL"),
    };

/// The texts of the settings.
const ALWAYS_UV: &CStr = c"Always verify";
const ALWAYS_UV_DETAILS: &CStr = c"Ask for the device unlock or PIN at every sign-in";
const PASSKEYS: &CStr = c"Passkeys";

/// The home screen and the settings, with the C structures NBGL reads while they are shown. They
/// point into this value, so it stays where it is once shown: the main loop owns it for the life
/// of the application.
pub struct Home {
    icon: nbgl_icon_details_t,
    always_uv: bool,
    info_types: [*const c_char; 2],
    info_contents: [*const c_char; 2],
    infos: nbgl_contentInfoList_t,
    switch: nbgl_contentSwitch_t,
    bar_texts: [*const c_char; 1],
    bar_tokens: [u8; 1],
    contents: [nbgl_content_t; 2],
    settings: nbgl_genericContents_t,
}

impl Home {
    /// The home screen with `glyph`, its switch showing `always_uv`.
    pub fn new(glyph: &NbglGlyph<'_>, always_uv: bool) -> Self {
        Self {
            icon: glyph.into(),
            always_uv,
            info_types: [c"Version".as_ptr(), c"Developer".as_ptr()],
            info_contents: [VERSION.as_ptr(), DEVELOPER.as_ptr()],
            infos: nbgl_contentInfoList_t::default(),
            switch: nbgl_contentSwitch_t::default(),
            bar_texts: [PASSKEYS.as_ptr()],
            bar_tokens: [PASSKEYS_TOKEN],
            contents: [nbgl_content_t::default(), nbgl_content_t::default()],
            settings: nbgl_genericContents_t::default(),
        }
    }

    /// The state the switch shows.
    pub fn always_uv(&self) -> bool {
        self.always_uv
    }

    /// Records the state the switch shows from now on.
    pub fn set_always_uv(&mut self, always_uv: bool) {
        self.always_uv = always_uv;
    }

    /// Shows the home screen and returns at once.
    pub fn show_and_return(&mut self) {
        self.show(INIT_HOME_PAGE as u8);
    }

    /// Shows the settings at `page` and returns at once: where the user was before the switch
    /// turned or the passkey list closed.
    pub fn show_settings(&mut self, page: SettingsPage) {
        self.show(page as u8);
    }

    // `tuneId` exists on the touch models only.
    #[allow(clippy::needless_update)]
    fn show(&mut self, page: u8) {
        self.infos = nbgl_contentInfoList_t {
            infoTypes: self.info_types.as_ptr(),
            infoContents: self.info_contents.as_ptr(),
            nbInfos: 2,
            ..Default::default()
        };
        self.switch = nbgl_contentSwitch_t {
            text: ALWAYS_UV.as_ptr(),
            subText: ALWAYS_UV_DETAILS.as_ptr(),
            initState: if self.always_uv { ON_STATE } else { OFF_STATE },
            token: ALWAYS_UV_TOKEN,
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            tuneId: TUNE_TAP_CASUAL,
            ..Default::default()
        };
        // Each content is a page of its own: the passkey list comes first, as the one users look
        // for, then the switch.
        self.contents = [
            nbgl_content_t {
                type_: BARS_LIST,
                content: nbgl_content_u {
                    barsList: nbgl_contentBarsList_t {
                        barTexts: self.bar_texts.as_ptr(),
                        tokens: self.bar_tokens.as_ptr(),
                        nbBars: 1,
                        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
                        tuneId: TUNE_TAP_CASUAL,
                        ..Default::default()
                    },
                },
                contentActionCallback: Some(settings_callback),
            },
            nbgl_content_t {
                type_: SWITCHES_LIST,
                content: nbgl_content_u {
                    switchesList: nbgl_pageSwitchesList_s {
                        switches: &self.switch,
                        nbSwitches: 1,
                    },
                },
                contentActionCallback: Some(settings_callback),
            },
        ];
        self.settings = nbgl_genericContents_t {
            callbackCallNeeded: false,
            __bindgen_anon_1: nbgl_genericContents_t__bindgen_ty_1 {
                contentsList: self.contents.as_ptr(),
            },
            nbContents: 2,
        };
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        let tagline = TAGLINE.as_ptr();
        #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
        let tagline = core::ptr::null();
        // SAFETY: the strings are static and the structures live in `self`, which stays in place
        // while the screen is shown; NBGL only reads them.
        unsafe {
            nbgl_useCaseHomeAndSettings(
                APP_NAME.as_ptr(),
                &self.icon,
                tagline,
                page,
                &self.settings,
                &self.infos,
                core::ptr::null(),
                Some(quit),
            );
        }
    }
}

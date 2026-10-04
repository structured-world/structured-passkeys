//! Device application: opens its NVM state, shows the home screen, runs the FIDO HID interface and
//! answers the Ledger APDU channel.

#![no_std]
#![no_main]

mod crypto;
mod hid;
mod storage;
mod ui;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::{self, CommError, CommandOrEvent, DecodedEventType, StatusWords};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use structured_passkeys_ctap::ctap2::Authenticator;
use structured_passkeys_ctap::storage::Store;
use zeroize::Zeroize;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

/// Name on the home screen; the same as `package.metadata.ledger.name`.
const APP_NAME: &str = "Structured Passkeys";

/// What the home screen of the touch devices says under the name; without it the SDK shows its
/// default line about signing transactions on a network. The Nano home screen shows the name
/// alone, and a tagline would take its place there.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
const TAGLINE: &str = "Passkeys and FIDO2 security key for signing in to websites and apps";

/// Class byte of the Ledger management channel; the SDK rejects other classes.
const CLA: u8 = 0xE0;

#[cfg(target_os = "apex_p")]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/key_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/key_64x64.png", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/key_nano_14x14.png", NBGL));

/// Largest CTAP response the application builds; getInfo needs a few dozen bytes.
const RESPONSE_SIZE: usize = 1024;

static RESPONSE: hid::Buffer<RESPONSE_SIZE> = hid::Buffer::new();

#[unsafe(no_mangle)]
extern "C" fn sample_main(_arg0: u32) {
    hid::start();
    let comm = io::init_comm(&COMM);
    comm.set_expected_cla(CLA);
    // SAFETY: `sample_main` runs once and is the only place that refers to the buffer.
    let response = unsafe { &mut *RESPONSE.get() };

    // Opening the store formats a fresh install and finishes a reset or a replacement that a
    // power loss interrupted. The authenticator initializes the PIN/UV auth protocols as at
    // power-up: opening the application is the power cycle of CTAP 2.2.
    // SAFETY: the only place that takes the NVM regions.
    let store = Store::open(unsafe { storage::NvmStorage::take() });
    let mut authenticator = Authenticator::new(hid::SETTINGS, crypto::DeviceCrypto, store);

    // The home screen carries the version page and the quit action.
    let home = NbglHomeAndSettings::new().glyph(&HOME_GLYPH);
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    let home = home.tagline(TAGLINE);
    let mut home = home.infos(
        APP_NAME,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    );
    home.show_and_return();

    // FIDO HID reports reach the transport through the USB class callbacks during each event;
    // the loop gives the transport its clock, answers the management channel and runs the
    // requests the transport hands out.
    loop {
        match comm.next_command_or_event() {
            CommandOrEvent::Command(command) => {
                // No management command is implemented: ISO/IEC 7816-4 5.6, SW 6D00
                // "instruction code not supported or invalid". The SDK names 0x6D00 `Unknown`;
                // its `BadIns` is 0x6E01.
                match command.reply(&[], StatusWords::Unknown) {
                    // An empty reply cannot overflow, and a reply that failed to leave the
                    // device has no one to report to: the host times out and the loop takes
                    // its next command.
                    Ok(()) | Err(CommError::Overflow | CommError::IoError) => {}
                }
            }
            CommandOrEvent::Event(DecodedEventType::Ticker) => hid::tick(),
            CommandOrEvent::Event(_) => {}
        }
        // Parsed while the transport holds the request; run once it is released, so the screen
        // of a waiting command can take events.
        if let Some(command) = hid::take_request(|request| authenticator.parse(request)) {
            let mut ui = ui::DeviceUi::new(comm, &mut home, &HOME_GLYPH);
            let length = authenticator.execute(command, &mut ui, &mut response[..]);
            hid::respond(&response[..length]);
            response[..length].zeroize();
        }
    }
}

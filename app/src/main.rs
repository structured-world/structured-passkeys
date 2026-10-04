//! Device application: opens its NVM state, shows the home screen, runs the FIDO HID interface and,
//! on the devices that have NFC, the FIDO applet, and answers the Ledger APDU channel.

#![no_std]
#![no_main]

mod crypto;
mod hid;
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
mod nfc;
mod storage;
mod ui;

use ledger_device_sdk::include_gif;
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::io::ApduTransport;
use ledger_device_sdk::io::{self, CommError, CommandOrEvent, DecodedEventType, StatusWords};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
use structured_passkeys_ctap::ctap2::{
    Authenticator, Link, MIN_MESSAGE_SIZE, MaxMsgSize, Settings, Transports,
};
use structured_passkeys_ctap::storage::Store;
use zeroize::Zeroize;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM, COMM_SIZE);

/// The largest CTAP request on every transport, reported as `maxMsgSize`: the 1024 bytes CTAP 2.2
/// §8 requires of every authenticator. Platforms keep their requests within it, and one size for
/// HID and NFC keeps one request buffer per transport small enough for the devices' RAM.
pub const MESSAGE_SIZE: usize = MIN_MESSAGE_SIZE as usize;

/// The SDK's APDU buffer: a packet type byte, then an extended APDU carrying a whole request (four
/// header bytes, a three-byte Lc, the message, a two-byte Le; 1034 bytes in all), or a response
/// part and its status word. The C SDK's IO buffer is set to the same size in `.cargo/config.toml`.
pub const COMM_SIZE: usize = MESSAGE_SIZE + 16;

/// The SDK's APDU channel with the buffer above.
pub type Comm = io::Comm<COMM_SIZE>;

/// The device facts getInfo reports, the same on every transport.
const SETTINGS: Settings = Settings {
    max_msg_size: match MaxMsgSize::new(MIN_MESSAGE_SIZE) {
        Ok(size) => size,
        Err(_) => panic!("the minimum is a valid maxMsgSize"),
    },
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    transports: Transports::UsbAndNfc,
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    transports: Transports::Usb,
};

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

/// Largest CTAP response the application builds, as large as a request: a response goes back
/// through the transport's request buffer.
const RESPONSE_SIZE: usize = MESSAGE_SIZE;

static RESPONSE: hid::Buffer<RESPONSE_SIZE> = hid::Buffer::new();

#[unsafe(no_mangle)]
extern "C" fn sample_main(_arg0: u32) {
    hid::start();
    // No expected class: the SDK would refuse the FIDO applet's classes over NFC; the management
    // channel checks its own below.
    let comm = io::init_comm(&COMM);
    // SAFETY: `sample_main` runs once and is the only place that refers to the buffer.
    let response = unsafe { &mut *RESPONSE.get() };
    let mut interfaces = ui::Interfaces::new();

    // Opening the store formats a fresh install and finishes a reset or a replacement that a
    // power loss interrupted. The authenticator initializes the PIN/UV auth protocols as at
    // power-up: opening the application is the power cycle of CTAP 2.2.
    // SAFETY: the only place that takes the NVM regions.
    let store = Store::open(unsafe { storage::NvmStorage::take() });
    let mut authenticator = Authenticator::new(SETTINGS, crypto::DeviceCrypto, store);

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

    // FIDO HID reports reach the transport through the USB class callbacks during each event, NFC
    // APDUs come as commands; the loop gives the transport its clock, answers the management
    // channel and runs the requests the transports hand out.
    loop {
        match comm.next_command_or_event() {
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            CommandOrEvent::Command(command) if command.transport() == Some(ApduTransport::Nfc) => {
                interfaces.nfc.command(command, hid::now_ms(), false);
            }
            CommandOrEvent::Command(command) => management(command),
            CommandOrEvent::Event(DecodedEventType::Ticker) => hid::tick(),
            CommandOrEvent::Event(_) => {}
        }
        // Parsed while the transport holds the request; run once it is released, so the screen
        // of a waiting command can take events.
        if let Some(command) = hid::take_request(|request| authenticator.parse(request)) {
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            sync_tap(&mut authenticator, &interfaces.nfc);
            let mut ui =
                ui::DeviceUi::new(comm, &mut home, &HOME_GLYPH, Link::Usb, &mut interfaces);
            let length = authenticator.execute(command, Link::Usb, &mut ui, &mut response[..]);
            hid::respond(&response[..length]);
            response[..length].zeroize();
        }
        #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
        if let Some(command) = interfaces
            .nfc
            .take_request(|request| authenticator.parse(request))
        {
            sync_tap(&mut authenticator, &interfaces.nfc);
            let mut ui =
                ui::DeviceUi::new(comm, &mut home, &HOME_GLYPH, Link::Nfc, &mut interfaces);
            let length = authenticator.execute(command, Link::Nfc, &mut ui, &mut response[..]);
            interfaces.nfc.respond(comm, &response[..length]);
            response[..length].zeroize();
        }
    }
}

/// Answers a command on the Ledger management channel. No management command is implemented:
/// ISO/IEC 7816-4 5.6, SW 6D00 "instruction code not supported or invalid", and 6E00 for a class
/// other than the channel's. The SDK names 0x6D00 `Unknown` (its `BadIns` is 0x6E01) and 0x6E00
/// `BadCla`.
pub fn management(command: io::Command<'_, COMM_SIZE>) {
    let status = if command.header().cla == CLA {
        StatusWords::Unknown
    } else {
        StatusWords::BadCla
    };
    match command.reply(&[], status) {
        // An empty reply cannot overflow, and a reply that failed to leave the device has no one
        // to report to: the host times out and the loop takes its next command.
        Ok(()) | Err(CommError::Overflow | CommError::IoError) => {}
    }
}

/// Gives the authenticator the NFC tap that still counts, before it runs a request.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
fn sync_tap<C, S>(authenticator: &mut Authenticator<C, S>, nfc: &nfc::Nfc)
where
    C: structured_passkeys_ctap::crypto::Crypto,
    S: structured_passkeys_ctap::storage::Storage,
{
    match nfc.tap_ms() {
        Some(tap_ms) => authenticator.nfc_tap(tap_ms),
        None => authenticator.nfc_ended(),
    }
}

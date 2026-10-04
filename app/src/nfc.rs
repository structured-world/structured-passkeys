//! The NFC interface of the devices that have one (Stax, Flex, Nano Gen5): command APDUs the SDK
//! receives over NFC go to the core crate's [`Applet`], which owns the protocol (selection,
//! chaining, status updates); this module moves the APDUs and keeps the tap.
//!
//! A request is run by the main loop like a HID request. Its NFCCTAP_MSG is set aside unanswered
//! meanwhile and answered on NFC once the response is ready, or earlier with a status update when
//! the request waits for the user and the client polls.

use core::sync::atomic::{AtomicBool, Ordering};

use ledger_device_sdk::io::{ApduTransport, CommError, Command, Reply};
use structured_passkeys_ctap::ctap2::StatusCode;
use structured_passkeys_ctap::nfc::{Apdu, Applet, Outcome};

use crate::hid::Buffer;
use crate::{COMM_SIZE, Comm, MESSAGE_SIZE};

static MESSAGE: Buffer<MESSAGE_SIZE> = Buffer::new();
/// The buffer was handed out.
static TAKEN: AtomicBool = AtomicBool::new(false);

/// The NFC applet and the state the main loop keeps around it.
pub struct Nfc {
    applet: Applet<MESSAGE_SIZE, &'static mut [u8; MESSAGE_SIZE]>,
    /// The applet holds a request the main loop has not taken yet.
    pending: bool,
    /// When the applet was last selected: the NFC tap, until CTAP ends.
    tap_ms: Option<u64>,
}

impl Nfc {
    /// The interface over its buffer; created once, by the main loop.
    ///
    /// # Panics
    ///
    /// When called a second time: the buffer is handed out once.
    pub fn new() -> Self {
        assert!(
            !TAKEN.swap(true, Ordering::Relaxed),
            "the NFC buffer is handed out once"
        );
        // SAFETY: the guard above makes this the only reference to the buffer.
        let message = unsafe { &mut *MESSAGE.get() };
        Self {
            applet: Applet::new(message),
            pending: false,
            tap_ms: None,
        }
    }

    /// Answers a command APDU that arrived over NFC at `now_ms`. A complete request stays in the
    /// applet for [`Nfc::take_request`], its command unanswered; while another request runs
    /// (`busy`), one is refused at once with CTAP1_ERR_CHANNEL_BUSY, as the HID transport does.
    pub fn command(&mut self, command: Command<'_, COMM_SIZE>, now_ms: u64, busy: bool) {
        let header = command.header();
        let apdu = Apdu {
            cla: header.cla,
            ins: header.ins,
            p1: header.p1,
            p2: header.p2,
            data: command.get_data(),
            ne: command.le(),
            extended: command.is_extended(),
        };
        // The SDK's receive buffer is not wiped: it lives in this application's RAM, which nothing
        // else on the device reads, and CTAP carries PIN material encrypted under the session key.
        match self.applet.command(&apdu) {
            Outcome::Reply(reply) => {
                send(command.reply(reply.data, Reply(reply.sw.0)));
            }
            Outcome::Selected(reply) => {
                self.tap_ms = Some(now_ms);
                send(command.reply(reply.data, Reply(reply.sw.0)));
            }
            Outcome::Request if busy => {
                // §8.2: "Channel busy. Client SHOULD retry the request after a short delay."
                if let Some(reply) = self.applet.respond(&[StatusCode::ChannelBusy as u8]) {
                    send(command.reply(reply.data, Reply(reply.sw.0)));
                }
            }
            // Answered on NFC when the response is ready, through `respond`.
            Outcome::Request => self.pending = true,
        }
        if !self.applet.selected() {
            self.tap_ms = None;
        }
    }

    /// The request the applet holds, given to `parse`; `None` when there is none.
    pub fn take_request<R>(&mut self, parse: impl FnOnce(&[u8]) -> R) -> Option<R> {
        if !core::mem::take(&mut self.pending) {
            return None;
        }
        self.applet.request().map(parse)
    }

    /// Sends the response to the request being run: on NFC now if its command is still
    /// unanswered, otherwise when the platform polls for it.
    pub fn respond(&mut self, comm: &mut Comm, response: &[u8]) {
        if let Some(reply) = self.applet.respond(response) {
            send(comm.send_on(ApduTransport::Nfc, reply.data, Reply(reply.sw.0)));
        }
    }

    /// The request being run waits for the user (`true`) or processes again (`false`); the
    /// first wait answers its command with a status update if the client polls.
    pub fn waiting_for_user(&mut self, comm: &mut Comm, waiting: bool) {
        if let Some(reply) = self.applet.wait_for_user(waiting) {
            send(comm.send_on(ApduTransport::Nfc, reply.data, Reply(reply.sw.0)));
        }
    }

    /// Whether the request being run is gone: the platform deselected or reselected the applet.
    pub fn request_ended(&self) -> bool {
        self.applet.cancelled()
    }

    /// The NFC tap that still counts: the time the applet was selected, until CTAP ends.
    pub const fn tap_ms(&self) -> Option<u64> {
        self.tap_ms
    }
}

/// An answer that failed to leave the device has no one to report to: the reader times out. An
/// answer cannot overflow, since the applet's parts are at most the buffer the SDK sends from.
fn send<T>(sent: Result<T, CommError>) {
    match sent {
        Ok(_) | Err(CommError::Overflow | CommError::IoError) => {}
    }
}

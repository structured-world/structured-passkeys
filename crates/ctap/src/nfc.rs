//! CTAP over NFC: the ISO/IEC 7816-4 binding of CTAP 2.2 §11.3.
//!
//! [`Applet`] is the FIDO applet as the platform sees it: applet selection (§11.3.3) and
//! deselection (§11.3.4), NFCCTAP_MSG with ISO/IEC 7816-4 command chaining (§11.3.6), response
//! chaining with GET RESPONSE, and NFCCTAP_GETRESPONSE with its status updates (§11.3.7). It
//! takes command APDUs already split into their fields and says what to answer; the device moves
//! the bytes. A complete request waits in the applet's buffer for the CTAP layer, whose response
//! goes back through the same buffer.
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::nfc::{AID, Applet, Apdu, Outcome, StatusWord, VERSION};
//!
//! let mut applet = Applet::<1024>::new([0; 1024]);
//! let select = Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: &AID, ne: Some(256), extended: false };
//! let Outcome::Selected(reply) = applet.command(&select) else { panic!("the FIDO AID selects") };
//! assert_eq!((reply.data, reply.sw), (&VERSION[..], StatusWord::OK));
//!
//! // authenticatorGetInfo in one short NFCCTAP_MSG.
//! let msg = Apdu { cla: 0x80, ins: 0x10, p1: 0x00, p2: 0x00, data: &[0x04], ne: Some(256), extended: false };
//! assert!(matches!(applet.command(&msg), Outcome::Request));
//! assert_eq!(applet.request(), Some(&[0x04][..]));
//! let reply = applet.respond(&[0x00, 0xA0]).expect("the NFCCTAP_MSG is still unanswered");
//! assert_eq!((reply.data, reply.sw), (&[0x00, 0xA0][..], StatusWord::OK));
//! ```

use core::borrow::BorrowMut;

use zeroize::Zeroize;

use crate::ctaphid::KeepaliveStatus;

/// The FIDO applet AID (§11.3.3): RID A000000647, PIX 2F0001.
pub const AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// The version string a successful SELECT returns. §11.3.3: an authenticator that implements
/// CTAP2 only answers "FIDO_2_0"; CTAP1/U2F is not implemented here.
pub const VERSION: [u8; 8] = *b"FIDO_2_0";

/// CLA of the FIDO commands (§11.3.5.1).
const CLA_FIDO: u8 = 0x80;
/// CLA of a command that the next one continues (§11.3.6, ISO/IEC 7816-4 5.4.2).
const CLA_CHAINING: u8 = 0x90;
/// CLA of the interindustry commands SELECT and GET RESPONSE (ISO/IEC 7816-4 5.4.1).
const CLA_ISO: u8 = 0x00;

/// SELECT (ISO/IEC 7816-4 11.2.2) by DF name, first or only occurrence (§11.3.3).
const INS_SELECT: u8 = 0xA4;
const SELECT_BY_NAME: u8 = 0x04;
/// GET RESPONSE (ISO/IEC 7816-4 11.3.1): the next part of a chained response.
const INS_GET_RESPONSE: u8 = 0xC0;
/// NFCCTAP_MSG (§11.3.7.1).
const INS_MSG: u8 = 0x10;
/// NFCCTAP_GETRESPONSE (§11.3.7.2).
const INS_NFC_GETRESPONSE: u8 = 0x11;
/// NFCCTAP_CONTROL (§11.3.4).
const INS_CONTROL: u8 = 0x12;
/// The NFCCTAP_CONTROL control byte that ends CTAP: the applet deselects (§11.3.4).
const CONTROL_END: u8 = 0x01;

/// NFCCTAP_MSG P1: the client supports NFCCTAP_GETRESPONSE (§11.3.7.1); the other bits are RFU.
const P1_GETRESPONSE: u8 = 0x80;
/// NFCCTAP_GETRESPONSE P1 with which platforms cancel the request.
const P1_CANCEL: u8 = 0x11;

/// Response data bytes a short response carries at most (ISO/IEC 7816-4 5.1: Le 00 is 256).
const SHORT_NE: usize = 256;
/// Response data bytes an extended response carries at most (Le 0000 is 65536).
const EXTENDED_NE: usize = 65_536;

/// A status word (ISO/IEC 7816-4 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusWord(pub u16);

impl StatusWord {
    /// Normal processing (§11.3.5.2).
    pub const OK: Self = Self(0x9000);
    /// A status update of NFCCTAP_GETRESPONSE: the platform asks again (§11.3.5.2).
    pub const STATUS_UPDATE: Self = Self(0x9100);
    /// Wrong length (ISO/IEC 7816-4 5.6, 6700).
    pub const WRONG_LENGTH: Self = Self(0x6700);
    /// Conditions of use not satisfied (6985): the command does not fit the applet's state.
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);
    /// File or application not found (6A82): SELECT of another AID.
    pub const NOT_FOUND: Self = Self(0x6A82);
    /// Incorrect parameters P1-P2 (6A86).
    pub const WRONG_P1_P2: Self = Self(0x6A86);
    /// Instruction code not supported (6D00).
    pub const INS_NOT_SUPPORTED: Self = Self(0x6D00);
    /// Class not supported (6E00).
    pub const CLA_NOT_SUPPORTED: Self = Self(0x6E00);

    /// `61XX`: more response data waits for GET RESPONSE (ISO/IEC 7816-4 5.3.4). XX is the
    /// number of bytes left, or 00 for 256 and more.
    const fn more(remaining: usize) -> Self {
        let left = if remaining > 0xFF {
            0
        } else {
            remaining as u16
        };
        Self(0x6100 | left)
    }
}

/// A command APDU, split into its fields by the device's APDU layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Apdu<'a> {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// First parameter.
    pub p1: u8,
    /// Second parameter.
    pub p2: u8,
    /// The command data field.
    pub data: &'a [u8],
    /// Ne, the most response data bytes the command accepts, when it carries an Le field.
    pub ne: Option<usize>,
    /// The command used the extended form of the length fields.
    pub extended: bool,
}

impl Apdu<'_> {
    /// How the response to this command is framed.
    fn frame(&self) -> Frame {
        let most = if self.extended { EXTENDED_NE } else { SHORT_NE };
        // A command without Le accepts no response data by ISO/IEC 7816-4; a FIDO platform
        // always expects the CTAP response, so the largest response its encoding allows is
        // assumed instead of an empty one.
        Frame {
            ne: self.ne.unwrap_or(most).clamp(1, most),
        }
    }
}

/// The response data an answer carries, and its status word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    /// Response data, possibly empty.
    pub data: &'a [u8],
    /// The status word after the data.
    pub sw: StatusWord,
}

impl Reply<'static> {
    /// A reply without data.
    const fn status(sw: StatusWord) -> Self {
        Self { data: &[], sw }
    }
}

/// What a command APDU asks of the device.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// Answer the command with this reply.
    Reply(Reply<'a>),
    /// The FIDO applet was selected: answer with this reply. Placing the device in the field and
    /// selecting the applet is the NFC tap.
    Selected(Reply<'a>),
    /// A complete CTAP request waits in [`Applet::request`]: run it and give the response to
    /// [`Applet::respond`]. The command stays unanswered until then, or until
    /// [`Applet::wait_for_user`] answers it with a status update.
    Request,
}

/// Response framing taken from the command being answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    /// Response data bytes one answer carries at most.
    ne: usize,
}

/// Where the applet is in the exchange (§11.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not selected, or deselected (§11.3.4): only SELECT is accepted.
    Deselected,
    /// Selected, no request in progress.
    Idle,
    /// The first `len` bytes of a chained request have arrived (§11.3.6).
    Chaining { len: usize },
    /// A request of `len` bytes is with the CTAP layer.
    Running {
        len: usize,
        /// The client accepts status updates (NFCCTAP_MSG P1 bit 0x80).
        updates: bool,
        /// The NFCCTAP_MSG was answered with a status update; the response goes in answer to
        /// NFCCTAP_GETRESPONSE.
        deferred: bool,
        /// The platform cancelled the request with a poll; its response still goes out.
        cancel: bool,
        status: KeepaliveStatus,
        frame: Frame,
    },
    /// A response of `len` bytes waits for NFCCTAP_GETRESPONSE.
    Ready { len: usize },
    /// A response of `len` bytes is being read in parts; `offset` bytes are out.
    Sending { len: usize, offset: usize },
}

/// The FIDO applet: selection, framing and chaining of CTAP over NFC, over a buffer of `N` bytes
/// that holds a request, then its response.
///
/// `N` is the largest request the applet assembles; a longer one is answered with
/// CTAP2_ERR_REQUEST_TOO_LARGE. The buffer is the caller's, as for the HID transport.
pub struct Applet<const N: usize, S: BorrowMut<[u8; N]> = [u8; N]> {
    buffer: S,
    /// Leading bytes of `buffer` that may still hold message data.
    dirty: usize,
    state: State,
    /// The platform deselected or reselected the applet while a request ran.
    cancelled: bool,
}

impl<const N: usize, S: BorrowMut<[u8; N]>> Drop for Applet<N, S> {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// CTAP2_ERR_REQUEST_TOO_LARGE (CTAP 2.2 §8.2): the CTAP answer to a chained request longer than
/// the buffer.
const REQUEST_TOO_LARGE: [u8; 1] = [0x39];

impl<const N: usize, S: BorrowMut<[u8; N]>> Applet<N, S> {
    /// An applet over `buffer`, not selected yet. The buffer's content is never read before it is
    /// written.
    pub const fn new(buffer: S) -> Self {
        Self {
            buffer,
            dirty: 0,
            state: State::Deselected,
            cancelled: false,
        }
    }

    fn bytes(&self) -> &[u8; N] {
        self.buffer.borrow()
    }

    fn bytes_mut(&mut self) -> &mut [u8; N] {
        self.buffer.borrow_mut()
    }

    /// Wipes whatever a request or response left in the buffer.
    fn wipe(&mut self) {
        let dirty = self.dirty.min(N);
        self.bytes_mut()[..dirty].zeroize();
        self.dirty = 0;
    }

    /// Ends what is in progress: a request being assembled or run, or a response being read.
    fn drop_exchange(&mut self) {
        if matches!(self.state, State::Running { .. }) {
            self.cancelled = true;
        }
        self.wipe();
    }

    /// Answers one command APDU.
    pub fn command<'a>(&'a mut self, apdu: &Apdu<'_>) -> Outcome<'a> {
        // The device copied the last part of a response out before taking this command.
        if self.state == State::Idle {
            self.wipe();
        }
        // A chain is a run of consecutive parts (ISO/IEC 7816-4 5.4.2): any other command, a
        // poll or a SELECT that selects nothing included, ends it, so the next part never lands
        // after a stale prefix.
        if apdu.ins != INS_MSG || !matches!(apdu.cla, CLA_FIDO | CLA_CHAINING) {
            self.abandon_chain();
        }
        // SELECT is accepted in every state; selecting the FIDO applet again starts over
        // (§11.3.3: the client selects before any other command).
        if apdu.cla == CLA_ISO && apdu.ins == INS_SELECT {
            return self.select(apdu);
        }
        if self.state == State::Deselected {
            // §11.3.4: CTAP commands are ignored until the applet is selected again; the
            // command still gets an answer, since every APDU does.
            return Outcome::Reply(Reply::status(StatusWord::CONDITIONS_NOT_SATISFIED));
        }
        // A request being run takes only NFCCTAP_GETRESPONSE, deselection and selection.
        if let State::Running { .. } = self.state {
            return Outcome::Reply(self.while_running(apdu));
        }
        // The rest of a chained response is read with GET RESPONSE (ISO/IEC 7816-4 5.3.4), in
        // either class; any other command drops it, so a response is never read out of order.
        if apdu.ins == INS_GET_RESPONSE && matches!(apdu.cla, CLA_ISO | CLA_FIDO) {
            return Outcome::Reply(self.next_part(apdu));
        }
        if apdu.cla == CLA_FIDO && apdu.ins == INS_NFC_GETRESPONSE {
            return Outcome::Reply(self.deferred_response(apdu));
        }
        if matches!(self.state, State::Ready { .. } | State::Sending { .. }) {
            self.wipe();
            self.state = State::Idle;
        }
        match (apdu.cla, apdu.ins) {
            (CLA_FIDO | CLA_CHAINING, INS_MSG) => self.message(apdu),
            (CLA_FIDO, INS_CONTROL) => Outcome::Reply(self.control(apdu)),
            (CLA_FIDO | CLA_CHAINING | CLA_ISO, _) => {
                Outcome::Reply(Reply::status(StatusWord::INS_NOT_SUPPORTED))
            }
            _ => Outcome::Reply(Reply::status(StatusWord::CLA_NOT_SUPPORTED)),
        }
    }

    /// A chain that another command interrupted is dropped (ISO/IEC 7816-4 5.4.2: a chain is
    /// a run of consecutive commands).
    fn abandon_chain(&mut self) {
        if let State::Chaining { .. } = self.state {
            self.wipe();
            self.state = State::Idle;
        }
    }

    fn select<'a>(&'a mut self, apdu: &Apdu<'_>) -> Outcome<'a> {
        if apdu.p1 != SELECT_BY_NAME || apdu.p2 != 0x00 {
            return Outcome::Reply(Reply::status(StatusWord::WRONG_P1_P2));
        }
        if apdu.data != AID {
            // Readers probe other applications first (an NDEF tag, a payment AID); an absent
            // application is 6A82, and the FIDO applet's state is not touched by the probe.
            return Outcome::Reply(Reply::status(StatusWord::NOT_FOUND));
        }
        self.drop_exchange();
        self.state = State::Idle;
        Outcome::Selected(Reply {
            data: &VERSION,
            sw: StatusWord::OK,
        })
    }

    /// NFCCTAP_CONTROL (§11.3.4): END CTAP_MSG deselects the applet.
    fn control(&mut self, apdu: &Apdu<'_>) -> Reply<'static> {
        self.abandon_chain();
        if apdu.p1 != CONTROL_END || apdu.p2 != 0x00 {
            return Reply::status(StatusWord::WRONG_P1_P2);
        }
        // §11.3.4: the command is CLA, INS, P1 and P2 alone; one with data is malformed and
        // ends nothing.
        if !apdu.data.is_empty() {
            return Reply::status(StatusWord::WRONG_LENGTH);
        }
        self.drop_exchange();
        self.state = State::Deselected;
        Reply::status(StatusWord::OK)
    }

    /// NFCCTAP_MSG (§11.3.7.1), either whole or as one part of a chain (§11.3.6).
    fn message<'a>(&'a mut self, apdu: &Apdu<'_>) -> Outcome<'a> {
        // §11.3.7.1: P1 bit 0x80 announces NFCCTAP_GETRESPONSE support, the rest of P1 and P2
        // are RFU and MUST be zero.
        if apdu.p1 & !P1_GETRESPONSE != 0 || apdu.p2 != 0 {
            self.abandon_chain();
            return Outcome::Reply(Reply::status(StatusWord::WRONG_P1_P2));
        }
        let start = match self.state {
            State::Chaining { len } => len,
            _ => 0,
        };
        let Some(len) = start.checked_add(apdu.data.len()).filter(|&len| len <= N) else {
            // The request cannot be held: the CTAP answer for it (§8.2), in place of the chain.
            self.wipe();
            self.state = State::Idle;
            return Outcome::Reply(Reply {
                data: &REQUEST_TOO_LARGE,
                sw: StatusWord::OK,
            });
        };
        self.bytes_mut()[start..len].copy_from_slice(apdu.data);
        self.dirty = self.dirty.max(len);
        if apdu.cla == CLA_CHAINING {
            self.state = State::Chaining { len };
            return Outcome::Reply(Reply::status(StatusWord::OK));
        }
        self.cancelled = false;
        self.state = State::Running {
            len,
            updates: apdu.p1 & P1_GETRESPONSE != 0,
            deferred: false,
            cancel: false,
            status: KeepaliveStatus::Processing,
            frame: apdu.frame(),
        };
        Outcome::Request
    }

    /// The commands a running request accepts.
    fn while_running(&mut self, apdu: &Apdu<'_>) -> Reply<'static> {
        match (apdu.cla, apdu.ins) {
            // §11.3.7.2: a status update until the response is ready. Its P1 is RFU there;
            // platforms (python-fido2) send 0x11 to cancel the request, which ends it like
            // CTAPHID_CANCEL (§11.2.9.1.5) rather than leaving it to time out.
            (CLA_FIDO, INS_NFC_GETRESPONSE) => {
                if !getresponse_parameters(apdu) {
                    return Reply::status(StatusWord::WRONG_P1_P2);
                }
                let State::Running {
                    deferred: true,
                    cancel,
                    status,
                    ..
                } = &mut self.state
                else {
                    return Reply::status(StatusWord::CONDITIONS_NOT_SATISFIED);
                };
                if apdu.p1 == P1_CANCEL {
                    *cancel = true;
                }
                Reply {
                    data: status_byte(*status),
                    sw: StatusWord::STATUS_UPDATE,
                }
            }
            // The platform ends CTAP: the request is cancelled with the applet.
            (CLA_FIDO, INS_CONTROL) => self.control(apdu),
            // One request at a time: the platform waits for the response of this one.
            _ => Reply::status(StatusWord::CONDITIONS_NOT_SATISFIED),
        }
    }

    /// NFCCTAP_GETRESPONSE (§11.3.7.2) once the response is ready.
    fn deferred_response<'a>(&'a mut self, apdu: &Apdu<'_>) -> Reply<'a> {
        if !getresponse_parameters(apdu) {
            return Reply::status(StatusWord::WRONG_P1_P2);
        }
        let State::Ready { len } = self.state else {
            return Reply::status(StatusWord::CONDITIONS_NOT_SATISFIED);
        };
        self.send(len, 0, apdu.frame())
    }

    /// GET RESPONSE: the next part of a chained response.
    fn next_part<'a>(&'a mut self, apdu: &Apdu<'_>) -> Reply<'a> {
        // ISO/IEC 7816-4 7.6.1: P1-P2 are 0000; other values are refused before the response
        // advances.
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Reply::status(StatusWord::WRONG_P1_P2);
        }
        let State::Sending { len, offset } = self.state else {
            return Reply::status(StatusWord::CONDITIONS_NOT_SATISFIED);
        };
        self.send(len, offset, apdu.frame())
    }

    /// The part of the response from `offset` that `frame` allows, `61XX` while more is left
    /// (ISO/IEC 7816-4 5.3.4; §11.3.6: a short command gets a chained response, an extended one
    /// an extended response).
    fn send(&mut self, len: usize, offset: usize, frame: Frame) -> Reply<'_> {
        let end = offset.checked_add(frame.ne).map_or(len, |end| end.min(len));
        let remaining = len
            .checked_sub(end)
            .expect("the part ends within the response");
        if remaining == 0 {
            // The last part: the buffer is wiped once the device has copied it, at the next
            // command or response.
            self.state = State::Idle;
            Reply {
                data: &self.bytes()[offset..end],
                sw: StatusWord::OK,
            }
        } else {
            self.state = State::Sending { len, offset: end };
            Reply {
                data: &self.bytes()[offset..end],
                sw: StatusWord::more(remaining),
            }
        }
    }

    /// The CTAP request of the last [`Outcome::Request`], while it is being run.
    pub fn request(&self) -> Option<&[u8]> {
        match self.state {
            State::Running { len, .. } => Some(&self.bytes()[..len]),
            _ => None,
        }
    }

    /// Whether the FIDO applet is selected: from a SELECT of its AID until NFCCTAP_CONTROL ends
    /// CTAP (§11.3.3, §11.3.4).
    pub fn selected(&self) -> bool {
        self.state != State::Deselected
    }

    /// Whether the request being run is to end: the platform cancelled it with a poll, or it is
    /// gone with the applet deselected or reselected.
    pub const fn cancelled(&self) -> bool {
        match self.state {
            State::Running { cancel, .. } => cancel || self.cancelled,
            _ => true,
        }
    }

    /// The request being run now waits for the user (`true`) or processes again (`false`). The
    /// first time it waits, and if the client accepts status updates, its NFCCTAP_MSG is answered
    /// with one (§11.3.7.1: "it MAY return a 0x9100 result"), so the platform polls with
    /// NFCCTAP_GETRESPONSE meanwhile; a client without them waits for the response itself.
    pub fn wait_for_user(&mut self, waiting: bool) -> Option<Reply<'static>> {
        let State::Running {
            updates,
            deferred,
            status,
            ..
        } = &mut self.state
        else {
            return None;
        };
        *status = if waiting {
            KeepaliveStatus::UpNeeded
        } else {
            KeepaliveStatus::Processing
        };
        if !waiting || !*updates || *deferred {
            return None;
        }
        *deferred = true;
        Some(Reply {
            data: status_byte(*status),
            sw: StatusWord::STATUS_UPDATE,
        })
    }

    /// Takes the response to the request being run. While its NFCCTAP_MSG is unanswered, the
    /// first part of the response is the answer to give it; after a status update the response
    /// waits for NFCCTAP_GETRESPONSE and `None` is returned. A request the platform ended, or a
    /// response longer than the buffer, is dropped.
    pub fn respond(&mut self, response: &[u8]) -> Option<Reply<'_>> {
        let State::Running {
            deferred, frame, ..
        } = self.state
        else {
            return None;
        };
        let len = response.len();
        if len > N {
            self.wipe();
            self.state = State::Idle;
            return None;
        }
        self.wipe();
        self.bytes_mut()[..len].copy_from_slice(response);
        self.dirty = len;
        if deferred {
            self.state = State::Ready { len };
            return None;
        }
        Some(self.send(len, 0, frame))
    }
}

/// Whether the parameters of an NFCCTAP_GETRESPONSE are acceptable: §11.3.7.2 makes P1 and P2
/// RFU, zero; P1 0x11 is the cancel platforms send. Anything else is refused before the exchange
/// moves.
const fn getresponse_parameters(apdu: &Apdu<'_>) -> bool {
    apdu.p2 == 0 && (apdu.p1 == 0 || apdu.p1 == P1_CANCEL)
}

/// The status data of a status update: one byte, the keepalive status of §11.2.9.1.7.
const fn status_byte(status: KeepaliveStatus) -> &'static [u8] {
    match status {
        KeepaliveStatus::Processing => &[KeepaliveStatus::Processing as u8],
        KeepaliveStatus::UpNeeded => &[KeepaliveStatus::UpNeeded as u8],
    }
}

#[cfg(test)]
mod tests;

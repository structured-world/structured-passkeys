//! CTAPHID: the USB HID framing of CTAP (CTAP 2.2, §11.2 "USB Human Interface Device").
//!
//! [`Transport`] owns both directions of the interface: it turns received 64-byte reports into
//! requests for the CTAP layer, answers the transport commands itself, and hands out the reports
//! to send, one at a time, as the endpoint frees up. The device layer only moves reports. The
//! device stays busy from the first packet of a request until the last report of its response
//! has been handed out (§11.2.5.1), and the transport never allocates: the message buffer is a
//! const-generic array.
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::ctaphid::{BROADCAST_CID, DeviceInfo, Event, REPORT_SIZE, Transport};
//!
//! let info = DeviceInfo { version: [0, 1, 0], cbor: true, msg: false };
//! let mut transport = Transport::<1024>::new(info, [0; 1024]);
//! // CTAPHID_INIT on the broadcast channel with an 8-byte nonce.
//! let mut report = [0u8; REPORT_SIZE];
//! report[..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
//! report[4] = 0x86;
//! report[6] = 8;
//! report[7..15].copy_from_slice(b"nonce123");
//! assert_eq!(transport.receive(&report, 0), Event::None);
//! // The INIT response is one report on the broadcast channel: the device hands it to its stack
//! // (`taken`), the host reads it (`sent`), and nothing is left to send.
//! let response = transport.next_report().expect("INIT is answered by the transport");
//! assert_eq!((&response[..4], response[4], response[6]), (&[0xFF; 4][..], 0x86, 17));
//! transport.taken(0);
//! transport.sent();
//! assert_eq!(transport.next_report(), None);
//! ```

use core::borrow::BorrowMut;
use core::num::NonZeroU64;

use zeroize::Zeroize;

/// Size of a CTAPHID report in bytes (§11.2.8.1, full-speed endpoints).
pub const REPORT_SIZE: usize = 64;

/// One HID report.
pub type Report = [u8; REPORT_SIZE];

/// Channel used to allocate channels (§11.2.3).
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Largest payload the framing can carry: `64 - 7 + 128 * (64 - 5)` (§11.2.4).
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA + 128 * CONT_DATA;

/// Default time allowed between two packets of one request before it is abandoned, and between
/// two reports of a response before the host is considered gone; see
/// [`Transport::with_packet_timeout`]. §11.2.5.2 requires a timeout without fixing it. Hosts send
/// the packets of a message back to back and read responses as they come, so the margin is only
/// for host scheduling and USB latency; 500 ms leaves plenty, and a stalled channel still frees
/// the device quickly.
pub const DEFAULT_PACKET_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(500).expect("non-zero");

/// Longest gap between two keepalives while a request is processed (§11.2.9.1.7: "at least every
/// 100ms").
pub const KEEPALIVE_INTERVAL_MS: u64 = 100;

/// A keepalive is scheduled once half the interval has passed, so a device polling on a 100 ms
/// timer sends one on every tick even when the tick comes a little early.
const KEEPALIVE_DUE_MS: u64 = KEEPALIVE_INTERVAL_MS / 2;

/// CTAPHID protocol version reported by INIT (§11.2.9.1.3).
const PROTOCOL_VERSION: u8 = 2;

/// Payload bytes of an initialization packet: CID (4), CMD (1), BCNT (2) precede them.
const INIT_DATA: usize = REPORT_SIZE - 7;

/// Payload bytes of a continuation packet: CID (4), SEQ (1) precede them.
const CONT_DATA: usize = REPORT_SIZE - 5;

/// Highest sequence number of a continuation packet (§11.2.4).
const MAX_SEQ: u8 = 0x7F;

/// Bit 7 of the fifth byte tells an initialization packet from a continuation packet (§11.2.4).
const INIT_BIT: u8 = 0x80;

/// INIT request nonce length and response length (§11.2.9.1.3).
const NONCE_LEN: usize = 8;
const INIT_RESPONSE_LEN: usize = 17;

/// Transport errors waiting for the endpoint. Errors arise from host packets, at most one per
/// packet, and the queue drains one report per endpoint completion; when it is full the device
/// stops taking reports ([`Transport::can_receive`]) until the host reads.
const ERROR_QUEUE: usize = 4;

/// CTAPHID command codes (§11.2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Echo (§11.2.9.1.4).
    Ping = 0x01,
    /// CTAP1/U2F message (§11.2.9.1.1).
    Msg = 0x03,
    /// Channel lock, optional (§11.2.9.2.2).
    Lock = 0x04,
    /// Channel allocation and resynchronization (§11.2.9.1.3).
    Init = 0x06,
    /// Identify the device, optional (§11.2.9.2.1).
    Wink = 0x08,
    /// CTAP2 CBOR message (§11.2.9.1.2).
    Cbor = 0x10,
    /// Cancel the request being processed (§11.2.9.1.5).
    Cancel = 0x11,
    /// Progress of a request, device to host only (§11.2.9.1.7).
    Keepalive = 0x3B,
    /// Transport error, device to host only (§11.2.9.1.6).
    Error = 0x3F,
}

/// A command code that §11.2.9 does not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownCommand(pub u8);

impl TryFrom<u8> for Command {
    type Error = UnknownCommand;

    /// Reads a command code without the initialization-packet bit.
    fn try_from(code: u8) -> Result<Self, UnknownCommand> {
        Ok(match code {
            0x01 => Command::Ping,
            0x03 => Command::Msg,
            0x04 => Command::Lock,
            0x06 => Command::Init,
            0x08 => Command::Wink,
            0x10 => Command::Cbor,
            0x11 => Command::Cancel,
            0x3B => Command::Keepalive,
            0x3F => Command::Error,
            other => return Err(UnknownCommand(other)),
        })
    }
}

/// CTAPHID error codes (§11.2.9.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// The command is invalid or not implemented.
    InvalidCmd = 0x01,
    /// A parameter is invalid.
    InvalidPar = 0x02,
    /// BCNT is invalid for the request.
    InvalidLen = 0x03,
    /// The sequence number does not match.
    InvalidSeq = 0x04,
    /// The message timed out.
    MsgTimeout = 0x05,
    /// The device is busy with another channel.
    ChannelBusy = 0x06,
    /// The command requires a channel lock.
    LockRequired = 0x0A,
    /// The channel is not valid.
    InvalidChannel = 0x0B,
    /// Unspecified error.
    Other = 0x7F,
}

/// Status carried by a keepalive (§11.2.9.1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    /// Still processing the request.
    Processing = 1,
    /// Waiting for user presence.
    UpNeeded = 2,
}

/// What INIT reports about the device (§11.2.9.1.3). The capability flags are derived from it, so
/// they always match the commands the transport accepts; WINK is never claimed.
///
/// The optional LOCK and WINK (§11.2.9.2) are left out on purpose. LOCK reserves the device for
/// one channel for up to 10 seconds so a host can chain several messages; every request here is a
/// single message and the busy state already serializes them, so a lock would only let one client
/// shut the others out. WINK asks the device to show which one it is; this device puts every
/// request on its own screen and asks for confirmation there, so a wink would add nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Major, minor and build device version numbers (vendor defined).
    pub version: [u8; 3],
    /// `CTAPHID_CBOR` requests are accepted and CAPABILITY_CBOR is reported.
    pub cbor: bool,
    /// `CTAPHID_MSG` requests are accepted; otherwise CAPABILITY_NMSG is reported.
    pub msg: bool,
}

impl DeviceInfo {
    /// The capability byte of the INIT response (§11.2.9.1.3).
    const fn capabilities(&self) -> u8 {
        let cbor = if self.cbor { CAPABILITY_CBOR } else { 0 };
        let nmsg = if self.msg { 0 } else { CAPABILITY_NMSG };
        cbor | nmsg
    }

    /// Whether requests of `command` are handed to the CTAP layer.
    const fn accepts(&self, command: Command) -> bool {
        match command {
            Command::Cbor => self.cbor,
            Command::Msg => self.msg,
            Command::Ping | Command::Init => true,
            Command::Lock
            | Command::Wink
            | Command::Cancel
            | Command::Keepalive
            | Command::Error => false,
        }
    }
}

/// The device implements `CTAPHID_CBOR` (§11.2.9.1.3).
const CAPABILITY_CBOR: u8 = 0x04;
/// The device does NOT implement `CTAPHID_MSG` (§11.2.9.1.3).
const CAPABILITY_NMSG: u8 = 0x08;

/// What one received report means for the CTAP layer. Transport-level answers (INIT, PING echo,
/// ERROR) never show up here: they are queued for [`Transport::next_report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Nothing for the CTAP layer.
    None,
    /// A complete `CTAPHID_MSG` or `CTAPHID_CBOR` request, readable through
    /// [`Transport::request`] until [`Transport::respond`] answers it.
    Request {
        /// Channel of the request.
        cid: u32,
        /// `Command::Msg` or `Command::Cbor`.
        command: Command,
    },
    /// `CTAPHID_CANCEL` for the request being processed on `cid`: the CTAP layer ends it with
    /// `CTAP2_ERR_KEEPALIVE_CANCEL` (§11.2.9.1.5). Never answered by itself.
    Cancel {
        /// Channel of the cancelled request.
        cid: u32,
    },
}

/// Why [`Transport::respond`] did not take a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// No request is waiting for an answer: it was aborted (INIT on its channel, §11.2.5.3) or
    /// already answered.
    NotActive,
    /// The response is longer than the transport buffer.
    TooLong,
}

/// What taking the offered report changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// The queued error at this index goes.
    Error(usize),
    /// The pending keepalive goes.
    Keepalive,
    /// The response moves to this report; `None` after its last one.
    Frame(Option<Cursor>),
}

/// The next report of a message being sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cursor {
    /// The initialization packet.
    Init,
    /// The continuation packet with sequence `seq`, starting at payload byte `offset`.
    Cont { seq: u8, offset: usize },
}

/// Transaction state (§11.2.5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    /// Receiving the continuation packets of a request.
    Assembling {
        cid: u32,
        command: Command,
        len: usize,
        filled: usize,
        next_seq: u8,
        last_packet_ms: u64,
    },
    /// A request handed to the CTAP layer and not answered yet; its `len` bytes are in the
    /// buffer.
    Processing {
        cid: u32,
        /// `Command::Msg` or `Command::Cbor`; the response carries the same command.
        command: Command,
        len: usize,
        status: KeepaliveStatus,
        last_keepalive_ms: u64,
    },
    /// A response of `len` bytes in the buffer, sent report by report.
    Sending {
        cid: u32,
        command: Command,
        len: usize,
        /// The next report to hand out; `None` once the last one is out and waits for the host
        /// to read it ([`Transport::sent`]).
        next: Option<Cursor>,
        last_progress_ms: u64,
    },
}

/// Single-report error responses waiting for the endpoint, oldest first.
#[derive(Clone, Copy, Debug)]
struct ErrorQueue {
    entries: [(u32, ErrorCode); ERROR_QUEUE],
    len: usize,
}

impl ErrorQueue {
    const fn new() -> Self {
        Self {
            entries: [(0, ErrorCode::Other); ERROR_QUEUE],
            len: 0,
        }
    }

    const fn is_full(&self) -> bool {
        self.len >= ERROR_QUEUE
    }

    /// Queues an error. A full queue drops it; devices hold reports back while the queue is full
    /// ([`Transport::can_receive`]), so only a device that ignores that loses one.
    fn push(&mut self, cid: u32, code: ErrorCode) {
        if let Some(slot) = self.entries.get_mut(self.len) {
            *slot = (cid, code);
            self.len = self.len.checked_add(1).expect("len < ERROR_QUEUE here");
        }
    }

    /// The oldest error not addressed to `held`, whose errors wait for its response to end.
    fn first_except(&self, held: Option<u32>) -> Option<(usize, (u32, ErrorCode))> {
        let queued = self.entries.get(..self.len)?;
        let index = queued.iter().position(|&(cid, _)| Some(cid) != held)?;
        Some((index, queued[index]))
    }

    /// Removes the error at `index`, keeping the order of the others.
    fn remove(&mut self, index: usize) {
        if index >= self.len {
            return;
        }
        let next = index.checked_add(1).expect("index < len <= ERROR_QUEUE");
        self.entries.copy_within(next..self.len, index);
        self.len = self.len.checked_sub(1).expect("index < len");
    }
}

/// CTAPHID transport: reassembles requests up to `N` bytes, keeps channel and busy state, and
/// produces every report the device sends.
///
/// `N` is the device buffer, reported as `maxMsgSize`; it is at least one report's payload and
/// at most [`MAX_MESSAGE_SIZE`]. The same buffer holds a request, then its response. The buffer
/// is the caller's: an array owned by the transport, or a mutable reference to one, so a device
/// can keep a large buffer in zero-initialized static memory instead of building it on its stack.
pub struct Transport<const N: usize, S: BorrowMut<[u8; N]> = [u8; N]> {
    buffer: S,
    /// Leading bytes of `buffer` that may still hold message data.
    dirty: usize,
    state: State,
    errors: ErrorQueue,
    /// A keepalive for the request being processed waits for the endpoint.
    keepalive_pending: bool,
    /// A taken report sits in the IN endpoint until the host reads it ([`Transport::sent`]); it
    /// cannot be taken back, so nothing else is offered meanwhile.
    in_flight: bool,
    /// The last report taken was an error: the active channel's next report (a due keepalive or
    /// the response's next report) goes before the next error, so errors for other channels
    /// cannot starve it.
    error_sent: bool,
    last_cid: u32,
    info: DeviceInfo,
    packet_timeout_ms: u64,
}

impl<const N: usize, S: BorrowMut<[u8; N]>> Drop for Transport<N, S> {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl<const N: usize, S: BorrowMut<[u8; N]>> Transport<N, S> {
    const SIZE_IN_RANGE: () = assert!(N >= INIT_DATA && N <= MAX_MESSAGE_SIZE);

    /// Creates an idle transport over `buffer`, with no channel allocated and the
    /// [`DEFAULT_PACKET_TIMEOUT_MS`] packet timeout. The buffer's previous content is never
    /// read: every message is written before it is used.
    pub const fn new(info: DeviceInfo, buffer: S) -> Self {
        let () = Self::SIZE_IN_RANGE;
        Self {
            buffer,
            dirty: 0,
            state: State::Idle,
            errors: ErrorQueue::new(),
            keepalive_pending: false,
            in_flight: false,
            error_sent: false,
            last_cid: 0,
            info,
            packet_timeout_ms: DEFAULT_PACKET_TIMEOUT_MS.get(),
        }
    }

    /// Sets the time allowed between two packets of one request, and between two reports of a
    /// response; a message whose next packet comes this late or later is abandoned with
    /// `ERR_MSG_TIMEOUT` (§11.2.5.2), a response the host stopped reading is dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::num::NonZeroU64;
    /// use structured_passkeys_ctap::ctaphid::{DeviceInfo, Transport};
    ///
    /// let info = DeviceInfo { version: [0, 1, 0], cbor: true, msg: false };
    /// let timeout = NonZeroU64::new(750).expect("non-zero");
    /// let transport = Transport::<1024>::new(info, [0; 1024]).with_packet_timeout(timeout);
    /// assert_eq!(transport.packet_timeout_ms(), 750);
    /// ```
    #[must_use]
    pub const fn with_packet_timeout(mut self, timeout_ms: NonZeroU64) -> Self {
        self.packet_timeout_ms = timeout_ms.get();
        self
    }

    /// Time allowed between two packets of one message, in milliseconds.
    pub const fn packet_timeout_ms(&self) -> u64 {
        self.packet_timeout_ms
    }

    /// Largest request accepted, in bytes.
    pub const fn max_message_size(&self) -> usize {
        N
    }

    /// Whether the next report can be taken without losing an answer it may need: false while
    /// the queue of errors waiting for the endpoint is full. A device stops arming its OUT
    /// endpoint until it is true again, which holds back a host that sends faster than it reads.
    pub const fn can_receive(&self) -> bool {
        !self.errors.is_full()
    }

    /// Forgets every channel, transaction and queued report, as when the device is reset on the
    /// bus: hosts allocate their channels again (§11.2.3) and nothing stale is sent.
    pub fn restart(&mut self) {
        self.reset();
        self.errors = ErrorQueue::new();
        self.last_cid = 0;
        // A bus reset empties the endpoints too.
        self.in_flight = false;
    }

    /// Zeroes the message bytes held in the buffer: a request can carry PIN/UV material.
    fn wipe(&mut self) {
        let dirty = self.dirty;
        self.bytes_mut()[..dirty].zeroize();
        self.dirty = 0;
    }

    fn bytes(&self) -> &[u8; N] {
        self.buffer.borrow()
    }

    fn bytes_mut(&mut self) -> &mut [u8; N] {
        self.buffer.borrow_mut()
    }

    /// Ends the current transaction and wipes its data. A report already in the endpoint stays
    /// there (`in_flight`): only the host reading it frees the endpoint.
    fn reset(&mut self) {
        self.state = State::Idle;
        self.keepalive_pending = false;
        self.error_sent = false;
        self.wipe();
    }

    /// Records that the first `end` bytes of the buffer now hold message data.
    fn mark_dirty(&mut self, end: usize) {
        self.dirty = self.dirty.max(end);
    }

    /// A broken internal invariant: the transaction is dropped and the channel told so.
    fn broken(&mut self, cid: u32) -> Event {
        self.reset();
        self.error(cid, ErrorCode::Other)
    }

    fn error(&mut self, cid: u32, code: ErrorCode) -> Event {
        self.errors.push(cid, code);
        Event::None
    }

    /// Starts sending the `len`-byte message in the buffer; the device stays busy until its last
    /// report has been read ([`Transport::sent`]).
    fn send(&mut self, cid: u32, command: Command, len: usize, now_ms: u64) {
        self.state = State::Sending {
            cid,
            command,
            len,
            next: Some(Cursor::Init),
            last_progress_ms: now_ms,
        };
    }

    /// Abandons a message whose next packet is late (§11.2.5.2) and returns its channel.
    fn expire(&mut self, now_ms: u64) -> Option<u32> {
        let State::Assembling {
            cid,
            last_packet_ms,
            ..
        } = self.state
        else {
            return None;
        };
        if !self.late(last_packet_ms, now_ms) {
            return None;
        }
        self.reset();
        Some(cid)
    }

    /// Whether `now_ms` is at least the packet timeout after `since_ms`. A clock that went
    /// backwards counts as late: the age is unknown.
    fn late(&self, since_ms: u64, now_ms: u64) -> bool {
        now_ms
            .checked_sub(since_ms)
            .is_none_or(|age| age >= self.packet_timeout_ms)
    }

    /// Channel of the request handed out by [`Event::Request`] and not answered yet; `None`
    /// once it was answered, aborted by INIT, or never existed.
    pub fn active(&self) -> Option<u32> {
        match self.state {
            State::Processing { cid, .. } => Some(cid),
            _ => None,
        }
    }

    /// The command of the request waiting for an answer: `CTAPHID_CBOR` carries a CTAP2 request,
    /// `CTAPHID_MSG` a CTAP1/U2F message (§11.2.9.1.1).
    pub const fn request_command(&self) -> Option<Command> {
        match self.state {
            State::Processing { command, .. } => Some(command),
            _ => None,
        }
    }

    /// The payload of the request waiting for an answer.
    pub fn request(&self) -> Option<&[u8]> {
        match self.state {
            State::Processing { len, .. } => self.bytes().get(..len),
            _ => None,
        }
    }

    /// Answers the active request with `payload`; the device stays busy until the last report of
    /// the response has been handed out by [`Transport::next_report`].
    ///
    /// # Errors
    ///
    /// [`RespondError::NotActive`] when no request waits (the response is dropped),
    /// [`RespondError::TooLong`] when `payload` exceeds the buffer (the request stays active so
    /// the CTAP layer can answer with an error instead).
    pub fn respond(&mut self, payload: &[u8], now_ms: u64) -> Result<(), RespondError> {
        let State::Processing { cid, command, .. } = self.state else {
            return Err(RespondError::NotActive);
        };
        let len = payload.len();
        if len > N {
            return Err(RespondError::TooLong);
        }
        // The request is consumed: its bytes go before the response takes their place.
        self.wipe();
        self.bytes_mut()[..len].copy_from_slice(payload);
        self.mark_dirty(len);
        self.keepalive_pending = false;
        self.send(cid, command, len, now_ms);
        Ok(())
    }

    /// Sets what keepalives report for the active request; a change is reported at once
    /// (§11.2.9.1.7: "and whenever the status changes").
    pub fn set_status(&mut self, new: KeepaliveStatus) {
        if let State::Processing { status, .. } = &mut self.state
            && *status != new
        {
            *status = new;
            self.keepalive_pending = true;
        }
    }

    /// Called by the device loop without a report, at least every [`KEEPALIVE_INTERVAL_MS`]:
    /// times out a stalled message at its deadline (§11.2.5.2), schedules keepalives for the
    /// request being processed (§11.2.9.1.7) and drops a response the host stopped reading.
    pub fn poll(&mut self, now_ms: u64) {
        if let Some(cid) = self.expire(now_ms) {
            self.error(cid, ErrorCode::MsgTimeout);
            return;
        }
        match self.state {
            State::Processing {
                last_keepalive_ms, ..
            } => {
                // A clock that went backwards schedules one too: the gap is unknown.
                let due = now_ms
                    .checked_sub(last_keepalive_ms)
                    .is_none_or(|gap| gap >= KEEPALIVE_DUE_MS);
                if due
                    && let State::Processing {
                        last_keepalive_ms, ..
                    } = &mut self.state
                {
                    *last_keepalive_ms = now_ms;
                    self.keepalive_pending = true;
                }
            }
            State::Sending {
                last_progress_ms, ..
            } => {
                if !self.late(last_progress_ms, now_ms) {
                    return;
                }
                if self.in_flight {
                    // The host stopped reading with a report still in the endpoint: the rest
                    // of the response is dropped, and the device stays busy (§11.2.5.1) until
                    // that report is read, so it never precedes another transaction's answer.
                    if let State::Sending { next, .. } = &mut self.state {
                        *next = None;
                    }
                    // Nothing more of the response is sent, so its bytes go now.
                    self.wipe();
                } else {
                    self.reset();
                }
            }
            State::Idle | State::Assembling { .. } => {}
        }
    }

    /// The report to send next and what taking it changes: nothing while a report is in the
    /// endpoint; otherwise queued errors first, then the active channel's report (a due
    /// keepalive or the next report of the response being sent), except that right after an
    /// error the active channel's report goes first, so errors cannot starve it. An error for
    /// the channel whose response is being sent waits until that response is out, so the
    /// channel's own message is never split by another initialization packet (§11.2.4).
    fn plan(&self) -> Option<(Report, Step)> {
        if self.in_flight {
            return None;
        }
        let active = self.active_report();
        if self.error_sent
            && let Some(active) = active
        {
            return Some(active);
        }
        let sending = match self.state {
            State::Sending { cid, .. } => Some(cid),
            _ => None,
        };
        if let Some((index, (cid, code))) = self.errors.first_except(sending) {
            return Some((error_report(cid, code), Step::Error(index)));
        }
        active
    }

    /// The active channel's next report: a due keepalive for the request being processed, or
    /// the next report of the response being sent.
    fn active_report(&self) -> Option<(Report, Step)> {
        if let State::Processing { cid, status, .. } = self.state
            && self.keepalive_pending
        {
            return Some((keepalive_report(cid, status), Step::Keepalive));
        }
        self.next_frame()
    }

    /// The next report of the response being sent; `None` without one, or when its last report
    /// waits for `sent`.
    fn next_frame(&self) -> Option<(Report, Step)> {
        let State::Sending {
            cid,
            command,
            len,
            next: Some(next),
            ..
        } = self.state
        else {
            return None;
        };
        // `len <= N` whenever a message is sent ([`Transport::respond`], `complete`).
        let payload = self.bytes().get(..len)?;
        let (report, following) = frame(cid, command, payload, next);
        Some((report, Step::Frame(following)))
    }

    /// The next report to send once the endpoint is free, without consuming it: the device
    /// passes it to its stack and calls [`Transport::taken`] when the stack accepted it, so a
    /// report the stack refuses is offered again. After an abort the answer that replaced the
    /// aborted one comes instead. `None` when nothing waits.
    pub fn next_report(&self) -> Option<Report> {
        self.plan().map(|(report, _)| report)
    }

    /// The device's stack accepted the report [`Transport::next_report`] offered at `now_ms`;
    /// the following one is due next.
    pub fn taken(&mut self, now_ms: u64) {
        let Some((_, step)) = self.plan() else {
            return;
        };
        self.in_flight = true;
        self.error_sent = matches!(step, Step::Error(_));
        match step {
            Step::Error(index) => self.errors.remove(index),
            Step::Keepalive => self.keepalive_pending = false,
            Step::Frame(following) => {
                if let State::Sending {
                    next,
                    last_progress_ms,
                    ..
                } = &mut self.state
                {
                    // After the last report the device stays busy until the host has read it
                    // (`sent`).
                    *next = following;
                    *last_progress_ms = now_ms;
                }
            }
        }
    }

    /// The host read the report last taken; called by the device on every IN completion. After
    /// the last report of a response, the transaction ends and its data goes (§11.2.5.1: busy
    /// until the response is sent).
    pub fn sent(&mut self) {
        self.in_flight = false;
        if let State::Sending { next: None, .. } = self.state {
            self.reset();
        }
    }

    /// Handles one report received at `now_ms` (a monotonic millisecond clock).
    pub fn receive(&mut self, report: &Report, now_ms: u64) -> Event {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        // §11.2.5.2: the late packet of an abandoned message learns why.
        if self.expire(now_ms) == Some(cid) && report[4] & INIT_BIT == 0 {
            return self.error(cid, ErrorCode::MsgTimeout);
        }
        if report[4] & INIT_BIT == 0 {
            self.continuation(cid, report, now_ms)
        } else {
            self.initialization(cid, report, now_ms)
        }
    }

    fn continuation(&mut self, cid: u32, report: &Report, now_ms: u64) -> Event {
        let State::Assembling {
            cid: active,
            command,
            len,
            filled,
            next_seq,
            ..
        } = self.state
        else {
            // §11.2.5.4: spurious continuation packets are ignored.
            return Event::None;
        };
        if cid != active {
            // §11.2.5.1: another channel during a transaction is busy; a continuation packet is
            // not a request, so it is only dropped.
            return Event::None;
        }
        let seq = report[4];
        if seq != next_seq {
            self.reset();
            return self.error(cid, ErrorCode::InvalidSeq);
        }
        // `filled < len <= N` while assembling; a violation drops the message instead of
        // wrapping or panicking on host-driven offsets.
        let Some(remaining) = len.checked_sub(filled) else {
            return self.broken(cid);
        };
        let take = remaining.min(CONT_DATA);
        let (Some(end), Some(source_end)) = (filled.checked_add(take), 5usize.checked_add(take))
        else {
            return self.broken(cid);
        };
        let (Some(target), Some(source)) = (
            self.bytes_mut().get_mut(filled..end),
            report.get(5..source_end),
        ) else {
            return self.broken(cid);
        };
        target.copy_from_slice(source);
        self.mark_dirty(end);
        if end < len {
            // A message of at most N <= MAX_MESSAGE_SIZE bytes ends by sequence MAX_SEQ.
            let Some(next_seq) = seq.checked_add(1).filter(|next| *next <= MAX_SEQ) else {
                return self.broken(cid);
            };
            self.state = State::Assembling {
                cid,
                command,
                len,
                filled: end,
                next_seq,
                last_packet_ms: now_ms,
            };
            return Event::None;
        }
        self.complete(cid, command, len, now_ms)
    }

    fn initialization(&mut self, cid: u32, report: &Report, now_ms: u64) -> Event {
        let code = report[4] & !INIT_BIT;
        let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
        let command = Command::try_from(code);

        // §11.2.9.1.5 defines CANCEL with BCNT 0; one with a payload is not that request and is
        // ignored in every state. No CANCEL is ever answered.
        let cancel = command == Ok(Command::Cancel);
        if cancel && len != 0 {
            return Event::None;
        }

        match self.state {
            State::Processing { cid: active, .. } if cid == active => {
                return match command {
                    Ok(Command::Cancel) => Event::Cancel { cid },
                    // §11.2.5.3: INIT on the active channel aborts its transaction.
                    Ok(Command::Init) => {
                        self.reset();
                        self.start(cid, Command::Init, len, report, now_ms)
                    }
                    // The channel's own request is still being processed.
                    _ => self.error(cid, ErrorCode::ChannelBusy),
                };
            }
            State::Sending { cid: active, .. } if cid == active => {
                return match command {
                    // The answer is already on its way: there is nothing left to cancel.
                    Ok(Command::Cancel) => Event::None,
                    // §11.2.5.3: INIT aborts the transaction, its response included.
                    Ok(Command::Init) => {
                        self.reset();
                        self.start(cid, Command::Init, len, report, now_ms)
                    }
                    _ => self.error(cid, ErrorCode::ChannelBusy),
                };
            }
            State::Assembling { cid: active, .. } if cid == active => {
                // §11.2.9.1.5: CANCEL acts only on a CBOR request being processed and is ignored
                // otherwise, so the message keeps assembling. §11.2.5.3: INIT resynchronizes the
                // channel; any other initialization packet breaks the message being assembled.
                if cancel {
                    return Event::None;
                }
                self.reset();
                if command != Ok(Command::Init) {
                    return self.error(cid, ErrorCode::InvalidSeq);
                }
            }
            State::Processing { .. } | State::Sending { .. } | State::Assembling { .. } => {
                // §11.2.9.1.5: CANCEL on a non-active channel is ignored.
                if cancel {
                    return Event::None;
                }
                // §11.2.5.1: a request from another channel fails immediately.
                return self.error(cid, ErrorCode::ChannelBusy);
            }
            State::Idle => {}
        }

        // §11.2.9.1.5: CANCEL with nothing to cancel is ignored, on any channel.
        if cancel {
            return Event::None;
        }
        // §11.2.3: channel 0 is reserved, the broadcast channel only allocates, and any other
        // channel must have been allocated. Checked before the command, so an unknown command
        // there is still an invalid channel.
        let valid_channel = match cid {
            0 => false,
            BROADCAST_CID => command == Ok(Command::Init),
            _ => cid <= self.last_cid,
        };
        if !valid_channel {
            return self.error(cid, ErrorCode::InvalidChannel);
        }
        match command {
            Ok(command) => self.start(cid, command, len, report, now_ms),
            Err(UnknownCommand(_)) => self.error(cid, ErrorCode::InvalidCmd),
        }
    }

    /// Starts or completes a request on an idle device, on a channel already checked.
    fn start(
        &mut self,
        cid: u32,
        command: Command,
        len: usize,
        report: &Report,
        now_ms: u64,
    ) -> Event {
        // Only what INIT advertises is accepted: the optional LOCK and WINK (left out, see
        // `DeviceInfo`), device-to-host commands, CANCEL (handled before any request starts) and a
        // disabled MSG or CBOR are not.
        if !self.info.accepts(command) {
            return self.error(cid, ErrorCode::InvalidCmd);
        }
        if command == Command::Init && len != NONCE_LEN {
            return self.error(cid, ErrorCode::InvalidLen);
        }
        // A CBOR request starts with the CTAP command byte (§11.2.9.1.2) and a MSG request is a
        // U2F message (§11.2.9.1.1): without data there is no request to hand out.
        if matches!(command, Command::Cbor | Command::Msg) && len == 0 {
            return self.error(cid, ErrorCode::InvalidLen);
        }
        if len > N {
            return self.error(cid, ErrorCode::InvalidLen);
        }
        // At most INIT_DATA bytes, which N is at least.
        let take = len.min(INIT_DATA);
        let source_end = 7usize
            .checked_add(take)
            .expect("take is at most INIT_DATA, so it ends within the report");
        self.bytes_mut()[..take].copy_from_slice(&report[7..source_end]);
        self.mark_dirty(take);
        if take < len {
            self.state = State::Assembling {
                cid,
                command,
                len,
                filled: take,
                next_seq: 0,
                last_packet_ms: now_ms,
            };
            return Event::None;
        }
        self.complete(cid, command, len, now_ms)
    }

    /// Answers or hands out a fully received request of `len` bytes in the buffer.
    fn complete(&mut self, cid: u32, command: Command, len: usize, now_ms: u64) -> Event {
        match command {
            Command::Init => self.init(cid, now_ms),
            // The echo is the request itself, already in the buffer.
            Command::Ping => {
                self.send(cid, Command::Ping, len, now_ms);
                Event::None
            }
            Command::Msg | Command::Cbor => {
                self.state = State::Processing {
                    cid,
                    command,
                    len,
                    status: KeepaliveStatus::Processing,
                    last_keepalive_ms: now_ms,
                };
                Event::Request { cid, command }
            }
            // `start` lets only the four commands above assemble.
            Command::Lock
            | Command::Wink
            | Command::Cancel
            | Command::Keepalive
            | Command::Error => self.error(cid, ErrorCode::InvalidCmd),
        }
    }

    /// Answers INIT: allocates a channel on the broadcast channel, or confirms the channel it was
    /// received on (§11.2.9.1.3). The response replaces the nonce in the buffer.
    fn init(&mut self, cid: u32, now_ms: u64) -> Event {
        let channel = if cid == BROADCAST_CID {
            match self.last_cid.checked_add(1) {
                Some(next) if next != BROADCAST_CID => {
                    self.last_cid = next;
                    next
                }
                // Every channel identifier is taken; only a restart frees them.
                _ => {
                    self.reset();
                    return self.error(cid, ErrorCode::Other);
                }
            }
        } else {
            cid
        };
        // The nonce stays in bytes 0..8, where the response starts with it.
        let (version, capabilities) = (self.info.version, self.info.capabilities());
        let response = self.bytes_mut();
        response[8..12].copy_from_slice(&channel.to_be_bytes());
        response[12] = PROTOCOL_VERSION;
        response[13..16].copy_from_slice(&version);
        response[16] = capabilities;
        self.mark_dirty(INIT_RESPONSE_LEN);
        self.send(cid, Command::Init, INIT_RESPONSE_LEN, now_ms);
        Event::None
    }
}

/// The report at `cursor` of the `command` message carrying `payload` on `cid` (§11.2.4), and
/// the cursor of the following report, `None` after the last one. Unused bytes are zero.
fn frame(cid: u32, command: Command, payload: &[u8], cursor: Cursor) -> (Report, Option<Cursor>) {
    let mut report = [0u8; REPORT_SIZE];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    let (offset, take, header) = match cursor {
        Cursor::Init => {
            report[4] = command as u8 | INIT_BIT;
            let len = u16::try_from(payload.len())
                .expect("messages are at most MAX_MESSAGE_SIZE, which fits in BCNT");
            report[5..7].copy_from_slice(&len.to_be_bytes());
            (0, payload.len().min(INIT_DATA), 7usize)
        }
        Cursor::Cont { seq, offset } => {
            report[4] = seq;
            let remaining = payload
                .len()
                .checked_sub(offset)
                .expect("a cursor never passes the payload length");
            (offset, remaining.min(CONT_DATA), 5)
        }
    };
    let end = offset
        .checked_add(take)
        .expect("offset + take stays within the payload length");
    let report_end = header
        .checked_add(take)
        .expect("take fits the packet after its header");
    report[header..report_end].copy_from_slice(&payload[offset..end]);
    if end >= payload.len() {
        return (report, None);
    }
    let seq = match cursor {
        Cursor::Init => 0,
        // A payload of at most MAX_MESSAGE_SIZE ends by sequence MAX_SEQ, so a continuation
        // that is not the last one has a sequence below it.
        Cursor::Cont { seq, .. } => seq.checked_add(1).expect("sequence below MAX_SEQ here"),
    };
    (report, Some(Cursor::Cont { seq, offset: end }))
}

/// A one-report `CTAPHID_ERROR` response (§11.2.9.1.6).
fn error_report(cid: u32, code: ErrorCode) -> Report {
    frame(cid, Command::Error, &[code as u8], Cursor::Init).0
}

/// The keepalive report sent on `cid` while a request waits (§11.2.9.1.7).
fn keepalive_report(cid: u32, status: KeepaliveStatus) -> Report {
    frame(cid, Command::Keepalive, &[status as u8], Cursor::Init).0
}

#[cfg(test)]
mod tests;

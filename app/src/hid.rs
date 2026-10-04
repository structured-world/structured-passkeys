//! The FIDO HID interface: the application's own class for the C SDK's USB stack, in place of the
//! C SDK's `usbd_ledger_hid_u2f.c` and its CTAPHID (`lib_u2f`).
//!
//! The stack finds the class through the one symbol it references, `USBD_LEDGER_HID_U2F_class_info`;
//! defining it here keeps the linker from taking the C class out of the SDK archive. The class
//! declares a plain HID interface with the FIDO report descriptor (CTAP 2.2 §11.2.8) and moves raw
//! 64-byte reports between its endpoints and the core crate's [`Transport`], which owns the
//! protocol: framing, channels, busy state, timeouts and keepalives.
//!
//! Requests are run by the main loop, not in the class callbacks: a command that waits for the
//! user shows its screen and keeps taking events, which reach the class through the same
//! callbacks, so the transport goes on answering (keepalives, CANCEL, other channels) meanwhile.

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ffi::c_void;
use core::mem::MaybeUninit;

use structured_passkeys_ctap::ctaphid::{
    DeviceInfo, Event, KeepaliveStatus, REPORT_SIZE, Report, Transport,
};
use zeroize::Zeroize;

use crate::MESSAGE_SIZE;

/// Interval of the OS ticker events the main loop forwards to [`tick`]; the transport clock
/// advances by this much per tick. The ticker is the device's only clock: keepalives, which
/// CTAP 2.2 §11.2.9.1.7 says SHOULD go at least every 100 ms, follow it, and a device ticks a few
/// milliseconds slow (up to 106 ms measured on the Nano Gen5). It cannot be set faster, since NBGL
/// counts every tick as 100 ms for its own timers.
pub const TICK_MS: u64 = 100;

/// `USBD_StatusTypeDef` (`usbd_def.h`): one byte, as the SDK compiles C with `-fshort-enums`.
type UsbdStatus = u8;
const USBD_OK: UsbdStatus = 0;
const USBD_FAIL: UsbdStatus = 3;

/// `usbd_ledger_class_mask_e::USBD_LEDGER_CLASS_HID_U2F` (`usbd_ledger.h`).
const CLASS_HID_U2F: u8 = 0x04;

/// Endpoints of the interface: interrupt IN 0x81 and OUT 0x01, one report per transfer
/// (§11.2.8.1).
const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x01;
const EP_TYPE_INTERRUPT: u8 = 0x03;
const REPORT_LEN: u8 = REPORT_SIZE as u8;

/// The FIDO HID report descriptor (§11.2.8.2): usage page 0xF1D0, usage CTAPHID, one 64-byte input
/// and one 64-byte output report without report IDs.
#[rustfmt::skip] // One item per line, as the descriptor tables lay them out.
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, REPORT_LEN, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, REPORT_LEN, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

const HID_DESCRIPTOR_TYPE: u8 = 0x21;
const REPORT_DESCRIPTOR_TYPE: u8 = 0x22;
/// Offset of the HID descriptor in [`DESCRIPTORS`], after the interface descriptor.
const HID_DESCRIPTOR_AT: usize = 9;
const HID_DESCRIPTOR_LEN: usize = 9;

/// Interface, HID and endpoint descriptors (USB 2.0 §9.6.5, §9.6.6; HID 1.11 §6.2.1). The
/// interface is HID with subclass and protocol 0x00: the FIDO interface is no boot device
/// (§11.2.8.1). The stack writes the interface number into byte 2.
#[rustfmt::skip] // One descriptor per line.
const DESCRIPTORS: [u8; 32] = [
    // Interface: length, type, number (set by the stack), alternate setting, 2 endpoints,
    // class HID, subclass 0, protocol 0, string index of the product name.
    9, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x02,
    // HID 1.11, not localized, one report descriptor.
    9, HID_DESCRIPTOR_TYPE, 0x11, 0x01, 0x00, 0x01, REPORT_DESCRIPTOR_TYPE,
    REPORT_DESCRIPTOR.len() as u8, 0x00,
    // Interrupt IN endpoint, 64 bytes, polled every frame.
    7, 0x05, EP_IN, EP_TYPE_INTERRUPT, REPORT_LEN, 0x00, 0x01,
    // Interrupt OUT endpoint, 64 bytes, polled every frame.
    7, 0x05, EP_OUT, EP_TYPE_INTERRUPT, REPORT_LEN, 0x00, 0x01,
];

/// `USBD_SetupReqTypedef` (`usbd_def.h`).
#[repr(C)]
struct SetupRequest {
    bm_request: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
}

/// `usbd_end_point_info_t` (`usbd_ledger_types.h`).
#[repr(C)]
struct EndPointInfo {
    ep_in_addr: u8,
    ep_in_size: u16,
    ep_out_addr: u8,
    ep_out_size: u16,
    ep_type: u8,
}

type Init = unsafe extern "C" fn(*mut c_void, *mut c_void) -> UsbdStatus;
type Setup = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut SetupRequest) -> UsbdStatus;
type DataIn = unsafe extern "C" fn(*mut c_void, *mut c_void, u8) -> UsbdStatus;
type DataOut = unsafe extern "C" fn(*mut c_void, *mut c_void, u8, *mut u8, u16) -> UsbdStatus;
type SendPacket =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u8, *const u8, u16, u32) -> UsbdStatus;

/// `usbd_class_info_t` (`usbd_ledger_types.h`). The stack passes every function pointer through
/// `PIC()` before calling it, and skips the optional ones that are null.
#[repr(C)]
pub struct ClassInfo {
    class_type: u8,
    end_point: *const EndPointInfo,
    init: Option<Init>,
    de_init: Option<Init>,
    setup: Option<Setup>,
    ep0_rx_ready: Option<Init>,
    data_in: Option<DataIn>,
    data_out: Option<DataOut>,
    send_packet: Option<SendPacket>,
    is_busy: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    data_ready: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut u8, u16) -> i32>,
    setting: Option<unsafe extern "C" fn(u32, *mut u8, u16, *mut c_void)>,
    interface_descriptor_size: u8,
    interface_descriptor: *const u8,
    interface_association_descriptor_size: u8,
    interface_association_descriptor: *const u8,
    bos_descriptor_size: u8,
    bos_descriptor: *const u8,
    cookie: *mut c_void,
}

// SAFETY: the table is immutable and only read by the single-threaded USB stack.
unsafe impl Sync for ClassInfo {}

static END_POINT: EndPointInfo = EndPointInfo {
    ep_in_addr: EP_IN,
    ep_in_size: REPORT_SIZE as u16,
    ep_out_addr: EP_OUT,
    ep_out_size: REPORT_SIZE as u16,
    ep_type: EP_TYPE_INTERRUPT,
};

static DESCRIPTOR_BYTES: [u8; 32] = DESCRIPTORS;
static REPORT_DESCRIPTOR_BYTES: [u8; 34] = REPORT_DESCRIPTOR;

/// The class the stack's `USBD_LEDGER_start` registers for the FIDO interface. Not reachable from
/// Rust code, hence `#[used]`; the C stack references it by name.
#[used]
#[unsafe(export_name = "USBD_LEDGER_HID_U2F_class_info")]
static CLASS: ClassInfo = ClassInfo {
    class_type: CLASS_HID_U2F,
    end_point: &END_POINT,
    init: Some(init),
    de_init: Some(de_init),
    setup: Some(setup),
    ep0_rx_ready: None,
    data_in: Some(data_in),
    data_out: Some(data_out),
    send_packet: Some(send_packet),
    // Never busy for the stack: a FIDO response in flight must not hold up replies on the Ledger
    // APDU interface, which the stack waits on through this callback.
    is_busy: None,
    // Requests never go to the application through the stack's buffer: the transport hands them
    // out itself.
    data_ready: None,
    // The stack's U2F settings (versions, capabilities, first channel) are for the C transport;
    // the core transport has its own.
    setting: None,
    interface_descriptor_size: DESCRIPTORS.len() as u8,
    interface_descriptor: DESCRIPTOR_BYTES.as_ptr(),
    interface_association_descriptor_size: 0,
    interface_association_descriptor: core::ptr::null(),
    bos_descriptor_size: 0,
    bos_descriptor: core::ptr::null(),
    cookie: core::ptr::null_mut(),
};

unsafe extern "C" {
    fn USBD_LL_PrepareReceive(
        pdev: *mut c_void,
        ep_addr: u8,
        pbuf: *mut u8,
        size: u32,
    ) -> UsbdStatus;
    fn USBD_LL_Transmit(
        pdev: *mut c_void,
        ep_addr: u8,
        pbuf: *const u8,
        size: u32,
        timeout_ms: u32,
    ) -> UsbdStatus;
    fn USBD_CtlSendData(pdev: *mut c_void, pbuf: *mut u8, len: u32) -> UsbdStatus;
}

/// What INIT reports: the application version, CBOR only (U2F messages are not implemented).
const DEVICE_INFO: DeviceInfo = DeviceInfo {
    version: [
        version_part(env!("CARGO_PKG_VERSION_MAJOR")),
        version_part(env!("CARGO_PKG_VERSION_MINOR")),
        version_part(env!("CARGO_PKG_VERSION_PATCH")),
    ],
    cbor: true,
    msg: false,
};

/// A version number of at most 255, as INIT carries one byte per part.
const fn version_part(text: &str) -> u8 {
    let bytes = text.as_bytes();
    let mut value: u32 = 0;
    let mut at = 0;
    while at < bytes.len() {
        let digit = bytes[at];
        assert!(digit.is_ascii_digit(), "a version part is decimal");
        value = value * 10 + (digit - b'0') as u32;
        assert!(value <= 255, "a version part fits one byte");
        at += 1;
    }
    value as u8
}

/// Everything the class keeps between callbacks.
struct Hid {
    /// Requests of up to [`MESSAGE_SIZE`] bytes; a longer one is refused with ERR_INVALID_LEN at
    /// its initialization packet, and a PING echoes at most that much.
    transport: Transport<MESSAGE_SIZE, &'static mut [u8; MESSAGE_SIZE]>,
    /// The transport handed out a request the main loop has not taken yet.
    pending: bool,
    /// Channel of the request the main loop is running.
    running: Option<u32>,
    /// The transport handed out another request after the main loop took the running one: that
    /// one was aborted, even if the new request came on the same channel.
    superseded: bool,
    /// The host cancelled the request being run (CTAPHID_CANCEL on its channel).
    cancelled: bool,
    /// The stack's device handle, from the last callback that carried it; null before the
    /// interface is configured.
    pdev: *mut c_void,
    /// The OUT endpoint is not armed: the transport could not take a report yet
    /// ([`Transport::can_receive`]) or the stack refused to arm it. `pump` arms it again.
    out_unarmed: bool,
    /// Transport clock: [`TICK_MS`] per ticker event.
    now_ms: u64,
}

/// A zero-initialized static buffer, handed out once as `&'static mut`. The device's linker
/// script refuses initialized data in RAM, so everything large starts as zero bytes.
pub struct Buffer<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: each buffer is handed out once, on the only thread.
unsafe impl<const N: usize> Sync for Buffer<N> {}

impl<const N: usize> Buffer<N> {
    /// A zeroed buffer.
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    /// The buffer's address; the one place that owns the buffer turns it into its only
    /// reference.
    pub const fn get(&self) -> *mut [u8; N] {
        self.0.get()
    }
}

static MESSAGE: Buffer<MESSAGE_SIZE> = Buffer::new();

/// The class state, uninitialized until [`start`]. The application is single-threaded and the
/// stack calls the class only from `os_io_rx_evt`, which nothing here calls while holding the
/// state, so a borrow conflict is a programming error that `RefCell` turns into a panic instead
/// of aliasing.
struct Global {
    started: Cell<bool>,
    hid: UnsafeCell<MaybeUninit<RefCell<Hid>>>,
}

// SAFETY: there is one thread and no interrupt handler runs Rust code.
unsafe impl Sync for Global {}

static HID: Global = Global {
    started: Cell::new(false),
    hid: UnsafeCell::new(MaybeUninit::uninit()),
};

/// Sets up the class state; called once, first thing in the application, before any event can
/// reach the class.
pub fn start() {
    assert!(!HID.started.get(), "the FIDO HID class starts once");
    // SAFETY: the guard above makes this the only reference to the buffer.
    let message = unsafe { &mut *MESSAGE.get() };
    let hid = Hid {
        transport: Transport::new(DEVICE_INFO, message),
        pending: false,
        running: None,
        superseded: false,
        cancelled: false,
        pdev: core::ptr::null_mut(),
        out_unarmed: false,
        now_ms: 0,
    };
    // SAFETY: not started yet, so nothing refers to the slot.
    unsafe { (*HID.hid.get()).write(RefCell::new(hid)) };
    HID.started.set(true);
}

/// Runs `f` on the class state; `None` before [`start`].
fn with_hid<R>(f: impl FnOnce(&mut Hid) -> R) -> Option<R> {
    if !HID.started.get() {
        return None;
    }
    // SAFETY: `start` initialized the slot and nothing ever takes it apart.
    let cell = unsafe { (*HID.hid.get()).assume_init_ref() };
    let mut hid = cell
        .try_borrow_mut()
        .expect("the USB class is never re-entered");
    Some(f(&mut hid))
}

impl Hid {
    /// Notes a request for the main loop or a cancellation for the screen waiting on it, and
    /// sends what is due.
    fn handle(&mut self, event: Event) {
        match event {
            Event::Request { .. } => {
                self.pending = true;
                // The transport hands out a request only once idle, so one running request is
                // gone by now.
                self.superseded = self.running.is_some();
            }
            // The transport reports CANCEL only for the request being processed (§11.2.9.1.5).
            Event::Cancel { cid } => {
                if self.running == Some(cid) {
                    self.cancelled = true;
                }
            }
            Event::None => {}
        }
        self.pump();
    }

    /// Puts the next report into the IN endpoint if it is free (the transport offers none while
    /// the host has not read the last one), then arms the OUT endpoint if it was left unarmed.
    fn pump(&mut self) {
        if !self.pdev.is_null()
            && let Some(mut report) = self.transport.next_report()
        {
            // SAFETY: `pdev` is the handle the stack passed to the class; the stack copies the
            // report out before returning.
            let status = unsafe {
                USBD_LL_Transmit(self.pdev, EP_IN, report.as_ptr(), REPORT_SIZE as u32, 0)
            };
            // The copy here can carry request bytes (a PING echo); the stack has its own.
            report.zeroize();
            // A refused report stays with the transport, which offers it again on the next
            // completion or tick, or whatever replaced it if its transaction was aborted.
            if status == USBD_OK {
                self.transport.taken(self.now_ms);
            }
        }
        if self.out_unarmed {
            self.arm_out();
        }
    }

    /// Arms the OUT endpoint for the next report once the transport can take one; while it
    /// cannot, or when the stack refuses, the endpoint stays marked for `pump` to retry.
    fn arm_out(&mut self) {
        self.out_unarmed = true;
        if self.pdev.is_null() || !self.transport.can_receive() {
            return;
        }
        // SAFETY: `pdev` is the stack's handle; a null buffer lets the stack deliver the report
        // in its own transfer buffer.
        let status = unsafe {
            USBD_LL_PrepareReceive(self.pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32)
        };
        self.out_unarmed = status != USBD_OK;
    }

    /// Forgets the transaction and every queued report, wiping the buffer.
    fn reset(&mut self) {
        self.transport.restart();
        self.pending = false;
        // A request being run is gone with the transaction; its screen ends on its next check.
        self.out_unarmed = false;
    }
}

/// The request the transport handed out since the last call, given to `parse`; `None` when there
/// is none. The request stays in the transport's buffer, which the main loop must not hold while
/// it runs the command, so `parse` returns what the command needs.
pub fn take_request<R>(parse: impl FnOnce(&[u8]) -> R) -> Option<R> {
    with_hid(|hid| {
        if !core::mem::take(&mut hid.pending) {
            return None;
        }
        hid.running = hid.transport.active();
        hid.superseded = false;
        hid.cancelled = false;
        hid.transport.request().map(parse)
    })
    .flatten()
}

/// Refuses the request the transport handed out while a request from another transport runs: it
/// is answered at once with CTAP1_ERR_CHANNEL_BUSY (CTAP 2.2 §8.2: "Client SHOULD retry the
/// request after a short delay"), as the NFC applet answers in the other direction, rather than
/// run after the other one with its CANCEL unheard meanwhile.
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
pub fn refuse_request() {
    with_hid(|hid| {
        if core::mem::take(&mut hid.pending)
            && hid
                .transport
                .respond(
                    &[structured_passkeys_ctap::ctap2::StatusCode::ChannelBusy as u8],
                    hid.now_ms,
                )
                .is_ok()
        {
            hid.pump();
        }
    });
}

impl Hid {
    /// Whether the transport still processes the request the main loop is running.
    fn still_running(&self) -> bool {
        !self.superseded && self.running.is_some() && self.transport.active() == self.running
    }
}

/// Sends the response to the request being run. A request the host aborted meanwhile (INIT on
/// its channel, a bus reset) has no one to answer, so the response is dropped rather than given
/// to a request that took its place.
pub fn respond(response: &[u8]) {
    with_hid(|hid| {
        // The response is at most the transport's size: both buffers have the same maximum.
        if hid.still_running() && hid.transport.respond(response, hid.now_ms).is_ok() {
            hid.pump();
        }
        hid.running = None;
    });
}

/// Switches the keepalives of the request being run to "user presence needed" (§11.2.9.1.7) or
/// back to "processing".
pub fn waiting_for_user(waiting: bool) {
    with_hid(|hid| {
        if hid.still_running() {
            hid.transport.set_status(if waiting {
                KeepaliveStatus::UpNeeded
            } else {
                KeepaliveStatus::Processing
            });
            hid.pump();
        }
    });
}

/// Whether the request being run is gone: cancelled by the host, or aborted with its channel.
pub fn request_ended() -> bool {
    with_hid(|hid| hid.cancelled || !hid.still_running()).unwrap_or(true)
}

/// The device clock: milliseconds since the application started, advanced by [`tick`].
pub fn now_ms() -> u64 {
    with_hid(|hid| hid.now_ms).unwrap_or(0)
}

/// Advances the transport clock by one ticker interval: times out stalled messages, schedules
/// keepalives and sends what is due. Called by the main loop on every ticker event.
pub fn tick() {
    with_hid(|hid| {
        hid.now_ms = hid
            .now_ms
            .checked_add(TICK_MS)
            .expect("a u64 millisecond clock outlives the device");
        hid.transport.poll(hid.now_ms);
        hid.pump();
    });
}

/// Class `init`: the interface was configured; the transport starts over for the host.
unsafe extern "C" fn init(pdev: *mut c_void, _cookie: *mut c_void) -> UsbdStatus {
    let handled = with_hid(|hid| {
        hid.reset();
        hid.pdev = pdev;
        // A refused first arming is retried by `pump` like any other.
        hid.arm_out();
    });
    if handled.is_some() {
        return USBD_OK;
    }
    // SAFETY: before `start` nothing holds the endpoint back; `pdev` is the stack's handle; a
    // null buffer lets the stack deliver the report in its own transfer buffer.
    unsafe { USBD_LL_PrepareReceive(pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32) }
}

/// Class `de_init`: the interface is gone; nothing more can be sent, and whatever a request in
/// progress left in the buffer is wiped now rather than at the next configuration.
unsafe extern "C" fn de_init(_pdev: *mut c_void, _cookie: *mut c_void) -> UsbdStatus {
    with_hid(|hid| {
        hid.reset();
        hid.pdev = core::ptr::null_mut();
    });
    USBD_OK
}

/// Class `setup`: the standard and HID class requests addressed to the interface.
unsafe extern "C" fn setup(
    pdev: *mut c_void,
    _cookie: *mut c_void,
    request: *mut SetupRequest,
) -> UsbdStatus {
    // SAFETY: the stack passes the setup packet it is processing.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return USBD_FAIL;
    };
    // bmRequestType (USB 2.0 §9.3): bit 7 direction (1 device-to-host), bits 6..5 type (0
    // standard, 1 class), bits 4..0 recipient (1 interface). Every request is matched with its
    // direction, so one with a data stage the other way is refused rather than answered.
    const STANDARD_IN: u8 = 0x81;
    const STANDARD_OUT: u8 = 0x01;
    const CLASS_IN: u8 = 0xA1;
    const CLASS_OUT: u8 = 0x21;
    // Answers sent from statics: the stack may still read them after this call returns.
    static ZERO_STATUS: [u8; 2] = [0, 0];
    static ZERO: [u8; 1] = [0];
    static ZERO_REPORT: [u8; REPORT_SIZE] = [0; REPORT_SIZE];
    /// HID 1.11 §7.2.1: the report type in the high byte of wValue; 1 is Input.
    const INPUT_REPORT: u8 = 1;
    let send = |data: &'static [u8]| {
        let length = data.len().min(usize::from(request.w_length));
        // SAFETY: `pdev` is the stack's handle and `data` lives for the whole program; the stack
        // only reads it.
        unsafe { USBD_CtlSendData(pdev, data.as_ptr().cast_mut(), length as u32) }
    };
    match (request.bm_request, request.b_request) {
        // GET_STATUS: no remote wakeup, not halted (USB 2.0 §9.4.5).
        (STANDARD_IN, 0x00) => send(&ZERO_STATUS),
        // CLEAR_FEATURE: nothing to clear on the interface.
        (STANDARD_OUT, 0x01) => USBD_OK,
        // GET_DESCRIPTOR of the HID or report descriptor (HID 1.11 §7.1.1).
        (STANDARD_IN, 0x06) => match (request.w_value >> 8) as u8 {
            HID_DESCRIPTOR_TYPE => {
                send(&DESCRIPTOR_BYTES[HID_DESCRIPTOR_AT..HID_DESCRIPTOR_AT + HID_DESCRIPTOR_LEN])
            }
            REPORT_DESCRIPTOR_TYPE => send(&REPORT_DESCRIPTOR_BYTES),
            _ => USBD_FAIL,
        },
        // GET_INTERFACE: the only alternate setting is 0; SET_INTERFACE accepts only that one.
        (STANDARD_IN, 0x0A) => send(&ZERO),
        (STANDARD_OUT, 0x0B) if request.w_value == 0 => USBD_OK,
        // GET_REPORT, mandatory for every HID device (HID 1.11 §7.2.1): the Input report of
        // the descriptor, report ID 0. CTAPHID has no state to poll, so it reads as zeros;
        // reports flow through the interrupt endpoints.
        (CLASS_IN, 0x01) if request.w_value == u16::from(INPUT_REPORT) << 8 => send(&ZERO_REPORT),
        // No SET_REPORT (0x09): with an interrupt OUT endpoint declared, Output reports go
        // through it, not through the control pipe (HID 1.11 §4.4), so a second path for host
        // data would serve no host.
        // HID class requests (HID 1.11 §7.2): no idle rate and no boot protocol to keep, so
        // GET_IDLE and GET_PROTOCOL report zero and the SET requests are accepted as no-ops.
        (CLASS_IN, 0x02 | 0x03) => send(&ZERO),
        (CLASS_OUT, 0x0A | 0x0B) => USBD_OK,
        _ => USBD_FAIL,
    }
}

/// Class `data_in`: the host read the report in the IN endpoint; the next one can go.
unsafe extern "C" fn data_in(pdev: *mut c_void, _cookie: *mut c_void, _ep: u8) -> UsbdStatus {
    with_hid(|hid| {
        hid.pdev = pdev;
        hid.transport.sent();
        hid.pump();
    });
    USBD_OK
}

/// Class `data_out`: a report arrived on the OUT endpoint.
unsafe extern "C" fn data_out(
    pdev: *mut c_void,
    _cookie: *mut c_void,
    _ep: u8,
    packet: *mut u8,
    length: u16,
) -> UsbdStatus {
    // The received bytes, read in place and never copied: a request can carry PIN/UV material,
    // so they are wiped whatever the transfer turns out to be.
    let received: &mut [u8] = if packet.is_null() {
        &mut []
    } else {
        // SAFETY: the stack passes its transfer buffer holding `length` received bytes, and does
        // not touch it until the endpoint is armed again below.
        unsafe { core::slice::from_raw_parts_mut(packet, usize::from(length).min(REPORT_SIZE)) }
    };
    let handled = with_hid(|hid| {
        hid.pdev = pdev;
        // Every report on this interface is 64 bytes (§11.2.4, the report descriptor above); a
        // transfer of any other length is not a report and is dropped, never padded or cut into
        // one. `received` is bounded to 64 bytes for wiping, so the length is checked on its own.
        if usize::from(length) == REPORT_SIZE
            && let Ok(report) = <&Report>::try_from(&*received)
        {
            let event = hid.transport.receive(report, hid.now_ms);
            hid.handle(event);
        }
        // The transport keeps what it needs; the stack's copy is wiped before the endpoint can
        // receive into it again.
        received.zeroize();
        // A full error queue holds the host back, and a refused arming is retried: either way
        // the endpoint stays marked until `pump` arms it.
        hid.arm_out();
    });
    if handled.is_some() {
        return USBD_OK;
    }
    // Before `start` the transfer is dropped unread, and wiped all the same.
    received.zeroize();
    // SAFETY: before `start` nothing holds the endpoint back; `pdev` is the stack's handle.
    unsafe { USBD_LL_PrepareReceive(pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32) }
}

/// Class `send_packet`: the stack's path for messages built outside the class. Everything on
/// this interface is built by the transport, so nothing legitimately comes this way.
unsafe extern "C" fn send_packet(
    _pdev: *mut c_void,
    _cookie: *mut c_void,
    _packet_type: u8,
    _packet: *const u8,
    _length: u16,
    _timeout_ms: u32,
) -> UsbdStatus {
    USBD_FAIL
}

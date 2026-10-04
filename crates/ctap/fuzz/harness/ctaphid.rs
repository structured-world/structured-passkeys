//! CTAPHID transport driven by arbitrary bytes: the checks of the fuzz target.
//!
//! The input is a sequence of 66-byte steps: a time step in milliseconds, a flag byte, then one
//! 64-byte report. Flag bit 1 turns the step into a timer poll without a report; bit 0 answers the
//! request waiting after the step with as many bytes as the report's first byte says; bit 2 takes
//! only one report from the endpoint instead of all of them. Everything received and sent is
//! checked against the invariants the device and the host rely on.

use structured_passkeys_ctap::ctaphid::{
    BROADCAST_CID, Command, DeviceInfo, Event, REPORT_SIZE, Report, Transport,
};

/// Buffer size of the harness: small enough that BCNT above it is common.
const BUFFER: usize = 1024;

/// Bytes of one step: time step, flag, report.
const STEP: usize = 2 + REPORT_SIZE;

/// The host's view of what the device sent: allocated channels and messages being received.
#[derive(Default)]
struct Host {
    /// Channels handed out by INIT responses on the broadcast channel (§11.2.3).
    allocated: Vec<u32>,
    /// Messages whose initialization packet arrived: channel, command, BCNT, bytes so far, next
    /// sequence number.
    open: Vec<(u32, u8, usize, Vec<u8>, u8)>,
}

impl Host {
    /// Checks one report sent while `active` was the request being processed.
    fn read(&mut self, report: &Report, active: Option<u32>) {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if report[4] & 0x80 == 0 {
            let message = self
                .open
                .iter_mut()
                .find(|message| message.0 == cid)
                .expect("continuation packets only follow an initialization packet");
            assert_eq!(report[4], message.4, "sequence numbers ascend from 0");
            message.4 += 1;
            let take = (message.2 - message.3.len()).min(59);
            message.3.extend_from_slice(&report[5..5 + take]);
            assert!(report[5 + take..].iter().all(|&byte| byte == 0));
        } else {
            // INIT aborts a response on its channel (§11.2.5.3): the rest never comes.
            self.open.retain(|message| message.0 != cid);
            let command = report[4] & 0x7F;
            let bcnt = usize::from(u16::from_be_bytes([report[5], report[6]]));
            let take = bcnt.min(57);
            assert!(report[7 + take..].iter().all(|&byte| byte == 0));
            match Command::try_from(command) {
                Ok(Command::Error) => {
                    assert_eq!(bcnt, 1);
                    assert!(matches!(
                        report[7],
                        0x01 | 0x03 | 0x04 | 0x05 | 0x06 | 0x0B | 0x7F
                    ));
                }
                Ok(Command::Keepalive) => {
                    assert_eq!(bcnt, 1);
                    assert!(matches!(report[7], 1 | 2));
                    assert_eq!(
                        active,
                        Some(cid),
                        "keepalives only for the request processed"
                    );
                }
                Ok(Command::Init) => assert_eq!(bcnt, 17),
                Ok(Command::Ping | Command::Msg | Command::Cbor) => {
                    assert!(bcnt <= BUFFER);
                    // §11.2.3: messages only on allocated channels.
                    assert!(
                        self.allocated.contains(&cid),
                        "message on unallocated {cid}"
                    );
                }
                other => panic!("sent command {other:?}"),
            }
            self.open
                .push((cid, command, bcnt, report[7..7 + take].to_vec(), 0));
        }
        if let Some(index) = self
            .open
            .iter()
            .position(|message| message.3.len() == message.2)
        {
            let (cid, command, _, payload, _) = self.open.remove(index);
            if command == Command::Init as u8 {
                let channel =
                    u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                if cid == BROADCAST_CID {
                    // A fresh channel each time, never a reserved one.
                    assert!(channel != 0 && channel != BROADCAST_CID);
                    assert!(
                        !self.allocated.contains(&channel),
                        "channel {channel} reused"
                    );
                    self.allocated.push(channel);
                } else {
                    // INIT on a channel confirms that channel, which must be allocated.
                    assert_eq!(channel, cid);
                    assert!(self.allocated.contains(&cid), "INIT on unallocated {cid}");
                }
            }
        }
    }
}

/// Takes reports from the endpoint, all of them or only one, into the host; returns how many.
fn take(transport: &mut Transport<BUFFER>, host: &mut Host, now: u64, one: bool) -> usize {
    let mut count = 0;
    loop {
        let active = transport.active();
        let Some(report) = transport.next_report() else {
            return count;
        };
        // Looking does not consume: a report the stack refused is offered again unchanged.
        assert_eq!(
            transport.next_report(),
            Some(report),
            "offered twice, not taken"
        );
        transport.taken(now);
        // The host reads it, as the device reports on its IN completion.
        transport.sent();
        host.read(&report, active);
        count += 1;
        // A message is at most 129 reports, plus queued errors and a keepalive.
        assert!(count <= 140, "the transport never stops sending");
        if one {
            return count;
        }
    }
}

/// Runs one input; panics on any broken invariant.
pub fn run(data: &[u8]) {
    let info = DeviceInfo {
        version: [0, 1, 0],
        cbor: true,
        msg: true,
    };
    let mut transport = Transport::<BUFFER>::new(info, [0; BUFFER]);
    let mut host = Host::default();
    let mut now: u64 = 0;
    // Nothing is waiting for the endpoint.
    let mut drained = true;
    let (steps, _) = data.as_chunks::<STEP>();
    for step in steps {
        now += u64::from(step[0]);
        let flags = step[1];
        let mut report: Report = [0; REPORT_SIZE];
        report.copy_from_slice(&step[2..]);
        if flags & 2 == 2 {
            transport.poll(now);
        } else {
            let active_before = transport.active();
            // CTAPHID_CANCEL with the initialization bit.
            let is_cancel = report[4] == 0x91;
            match transport.receive(&report, now) {
                Event::None => {}
                Event::Request { cid, command } => {
                    assert!(matches!(command, Command::Msg | Command::Cbor));
                    // §11.2.3: requests only on allocated channels, never 0 or the broadcast one.
                    assert!(
                        host.allocated.contains(&cid),
                        "request on unallocated {cid}"
                    );
                    assert_eq!(transport.active(), Some(cid));
                    let request = transport.request().expect("a request waits");
                    assert!(request.len() <= BUFFER);
                }
                Event::Cancel { cid } => {
                    assert!(host.allocated.contains(&cid), "cancel on unallocated {cid}");
                    assert_eq!(active_before, Some(cid));
                    assert_eq!(transport.active(), Some(cid));
                }
            }
            if is_cancel && drained {
                // §11.2.9.1.5: CANCEL is never answered, whatever the state.
                assert_eq!(transport.next_report(), None, "CANCEL answered");
            }
        }
        if flags & 1 == 1 && transport.active().is_some() {
            // At most 255 * 4 = 1020 bytes, within the buffer.
            let response = vec![0xA5; usize::from(report[0]) * 4];
            transport
                .respond(&response, now)
                .expect("an active request takes an answer that fits the buffer");
            assert_eq!(transport.active(), None);
        }
        let one = flags & 4 == 4;
        let count = take(&mut transport, &mut host, now, one);
        drained = !one || count == 0;
    }
}

//! CTAPHID framing against the packet layouts and rules of CTAP 2.2 §11.2. Every expected report
//! is written out byte by byte from the specification tables, and the reports the transport sends
//! are read back with a separate parser of the §11.2.4 layout, never with the code under test.

use core::num::NonZeroU64;

use super::{
    BROADCAST_CID, Command, DEFAULT_PACKET_TIMEOUT_MS, DeviceInfo, ErrorCode, Event,
    KEEPALIVE_INTERVAL_MS, KeepaliveStatus, MAX_MESSAGE_SIZE, Report, RespondError, Transport,
    UnknownCommand,
};

const PACKET_TIMEOUT_MS: u64 = DEFAULT_PACKET_TIMEOUT_MS.get();

/// CBOR and MSG enabled: INIT reports capabilities 0x04 (CBOR, MSG implemented).
const INFO: DeviceInfo = DeviceInfo {
    version: [1, 2, 3],
    cbor: true,
    msg: true,
};
const NONCE: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];

/// A message read back from the reports the device sent: channel, command code, payload.
type Message = (u32, u8, Vec<u8>);

/// Initialization packet: CID (big endian), CMD | 0x80, BCNT, then up to 57 data bytes.
fn init_packet(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> Report {
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&bcnt.to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    report
}

/// Continuation packet: CID, SEQ (bit 7 clear), then up to 59 data bytes.
fn cont_packet(cid: u32, seq: u8, data: &[u8]) -> Report {
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = seq;
    report[5..5 + data.len()].copy_from_slice(data);
    report
}

/// Takes the next report as a device does: offered, then accepted by its stack at `now`.
fn take<const N: usize>(transport: &mut Transport<N>, now: u64) -> Option<Report> {
    let report = transport.next_report()?;
    transport.taken(now);
    Some(report)
}

/// Every report the transport has to send at `now`, in order, each read by the host as a device
/// would report it (`sent` after every endpoint completion).
fn drain<const N: usize>(transport: &mut Transport<N>, now: u64) -> Vec<Report> {
    let mut reports = Vec::new();
    while let Some(report) = take(transport, now) {
        transport.sent();
        reports.push(report);
        assert!(reports.len() <= 200, "the transport never stops sending");
    }
    reports
}

/// Reassembles sent reports into messages (§11.2.4): an initialization packet opens a message of
/// BCNT bytes on its channel, continuation packets of that channel fill it in sequence order.
fn messages(reports: &[Report]) -> Vec<Message> {
    let mut open: Vec<(u32, u8, usize, Vec<u8>, u8)> = Vec::new();
    let mut done = Vec::new();
    for report in reports {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if report[4] & 0x80 != 0 {
            assert!(
                !open.iter().any(|message| message.0 == cid),
                "a new message on {cid:#x} before the previous one ended"
            );
            let bcnt = usize::from(u16::from_be_bytes([report[5], report[6]]));
            let take = bcnt.min(57);
            assert!(
                report[7 + take..].iter().all(|&byte| byte == 0),
                "padding is zero"
            );
            open.push((cid, report[4] & 0x7F, bcnt, report[7..7 + take].to_vec(), 0));
        } else {
            let index = open
                .iter()
                .position(|message| message.0 == cid)
                .expect("a continuation packet of an open message");
            let message = &mut open[index];
            assert_eq!(report[4], message.4, "sequence numbers ascend from 0");
            message.4 += 1;
            let take = (message.2 - message.3.len()).min(59);
            assert!(
                report[5 + take..].iter().all(|&byte| byte == 0),
                "padding is zero"
            );
            message.3.extend_from_slice(&report[5..5 + take]);
        }
        if let Some(index) = open.iter().position(|message| message.3.len() == message.2) {
            let (cid, command, _, payload, _) = open.remove(index);
            done.push((cid, command, payload));
        }
    }
    assert!(open.is_empty(), "every message is sent whole");
    done
}

/// Everything sent at `now`, as messages.
fn sent<const N: usize>(transport: &mut Transport<N>, now: u64) -> Vec<Message> {
    messages(&drain(transport, now))
}

/// Feeds one report and returns the event and what the device sends right after it.
fn exchange<const N: usize>(
    transport: &mut Transport<N>,
    report: &Report,
    now: u64,
) -> (Event, Vec<Message>) {
    let event = transport.receive(report, now);
    (event, sent(transport, now))
}

/// Feeds one report that the transport answers by itself and returns the answer.
fn answer<const N: usize>(transport: &mut Transport<N>, report: &Report, now: u64) -> Message {
    let (event, mut replies) = exchange(transport, report, now);
    assert_eq!(event, Event::None, "answered by the transport");
    assert_eq!(replies.len(), 1, "exactly one answer: {replies:02x?}");
    replies.remove(0)
}

fn error(cid: u32, code: u8) -> Message {
    (cid, 0x3F, vec![code])
}

/// Allocates channels 1..=count on a fresh transport.
fn with_channels<const N: usize>(count: u32) -> Transport<N> {
    let mut transport = Transport::<N>::new(INFO, [0; N]);
    for _ in 0..count {
        answer(
            &mut transport,
            &init_packet(BROADCAST_CID, 0x06, 8, &NONCE),
            0,
        );
    }
    transport
}

/// Sends a one-byte CBOR request on `cid` at `now` and checks it is handed out.
fn cbor_request<const N: usize>(transport: &mut Transport<N>, cid: u32, now: u64) {
    let (event, replies) = exchange(transport, &init_packet(cid, 0x10, 1, &[0x04]), now);
    assert_eq!(
        event,
        Event::Request {
            cid,
            command: Command::Cbor
        }
    );
    assert_eq!(replies, Vec::<Message>::new());
    assert_eq!(transport.request(), Some(&[0x04][..]));
}

/// INIT on the broadcast channel allocates ascending channels and answers on the broadcast
/// channel with nonce, channel, protocol version 2, device version and capabilities
/// (§11.2.9.1.3); a wrong response layout breaks every host's channel setup.
#[test]
fn init_on_broadcast_allocates_ascending_channels() {
    let mut transport = Transport::<1024>::new(INFO, [0; 1024]);
    let first = answer(
        &mut transport,
        &init_packet(BROADCAST_CID, 0x06, 8, &NONCE),
        0,
    );
    let expected: Vec<u8> = [
        &NONCE[..],
        &[0x00, 0x00, 0x00, 0x01],
        &[0x02],
        &[1, 2, 3],
        &[0x04],
    ]
    .concat();
    assert_eq!(first, (BROADCAST_CID, 0x06, expected));
    let second = answer(
        &mut transport,
        &init_packet(BROADCAST_CID, 0x06, 8, &NONCE),
        0,
    );
    assert_eq!(second.2[8..12], [0x00, 0x00, 0x00, 0x02]);
}

/// INIT on an allocated channel resynchronizes it and answers with that same channel, on that
/// channel (§11.2.9.1.3).
#[test]
fn init_on_an_allocated_channel_confirms_it() {
    let mut transport = with_channels::<1024>(3);
    let (cid, command, payload) = answer(&mut transport, &init_packet(2, 0x06, 8, &NONCE), 0);
    assert_eq!((cid, command), (2, 0x06));
    assert_eq!(payload[8..12], [0, 0, 0, 2]);
}

/// INIT carries exactly an 8-byte nonce; any other BCNT is ERR_INVALID_LEN (§11.2.9.1.3).
#[test]
fn init_with_a_wrong_length_is_invalid_len() {
    let mut transport = Transport::<1024>::new(INFO, [0; 1024]);
    for bcnt in [0, 7, 9, 57] {
        let packet = init_packet(BROADCAST_CID, 0x06, bcnt, &[0; 9]);
        assert_eq!(
            answer(&mut transport, &packet, 0),
            error(BROADCAST_CID, 0x03),
            "BCNT {bcnt}"
        );
    }
}

/// Channel 0, unallocated channels, and the broadcast channel with anything but INIT are
/// ERR_INVALID_CHANNEL (§11.2.3), so a host cannot skip channel allocation.
#[test]
fn reserved_unallocated_and_broadcast_channels_are_invalid() {
    let mut transport = with_channels::<1024>(2);
    let cases = [
        init_packet(0, 0x06, 8, &NONCE),
        init_packet(0, 0x01, 0, &[]),
        init_packet(3, 0x06, 8, &NONCE),
        init_packet(3, 0x10, 1, &[0x04]),
        init_packet(BROADCAST_CID, 0x01, 0, &[]),
        init_packet(BROADCAST_CID, 0x10, 1, &[0x04]),
    ];
    for packet in cases {
        let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(
            answer(&mut transport, &packet, 0),
            error(cid, 0x0B),
            "{packet:02x?}"
        );
    }
}

/// The last channel identifier is never handed out twice and never becomes the broadcast
/// channel: allocation stops with ERR_OTHER.
#[test]
fn channel_allocation_stops_before_the_broadcast_channel() {
    let mut transport = Transport::<1024>::new(INFO, [0; 1024]);
    transport.last_cid = BROADCAST_CID - 1;
    let packet = init_packet(BROADCAST_CID, 0x06, 8, &NONCE);
    assert_eq!(
        answer(&mut transport, &packet, 0),
        error(BROADCAST_CID, 0x7F)
    );
}

/// PING echoes its payload, in one packet or reassembled from continuation packets
/// (§11.2.9.1.4, §11.2.4), and the echo is split at 57 then 59 bytes per packet.
#[test]
fn ping_echoes_single_and_multi_packet_payloads() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x01, 0, &[]), 0),
        (1, 0x01, Vec::new())
    );
    let data: Vec<u8> = (0..200u8).collect();
    for (seq, report) in [
        init_packet(1, 0x01, 200, &data[..57]),
        cont_packet(1, 0, &data[57..116]),
        cont_packet(1, 1, &data[116..175]),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            exchange(&mut transport, report, 0),
            (Event::None, vec![]),
            "{seq}"
        );
    }
    assert_eq!(
        transport.receive(&cont_packet(1, 2, &data[175..]), 3),
        Event::None
    );
    let reports = drain(&mut transport, 3);
    assert_eq!(reports.len(), 4, "57 + 59 + 59 + 25 bytes");
    let mut first = [0u8; 64];
    first[..7].copy_from_slice(&[0, 0, 0, 1, 0x81, 0x00, 200]);
    first[7..].copy_from_slice(&data[..57]);
    assert_eq!(reports[0], first);
    let mut last = [0u8; 64];
    last[..5].copy_from_slice(&[0, 0, 0, 1, 0x02]);
    last[5..30].copy_from_slice(&data[175..]);
    assert_eq!(reports[3], last);
    assert_eq!(messages(&reports), vec![(1, 0x01, data)]);
}

/// The largest message the framing allows, 7609 bytes in 129 packets with sequence numbers
/// 0..=127, is reassembled when the buffer is that large and echoed in 129 packets ending with
/// sequence 127 (§11.2.4).
#[test]
fn the_largest_message_is_reassembled_and_echoed() {
    let mut transport = with_channels::<MAX_MESSAGE_SIZE>(1);
    assert_eq!(MAX_MESSAGE_SIZE, 7609);
    let data: Vec<u8> = (0..7609u32).map(|byte| byte as u8).collect();
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 7609, &data[..57]), 0),
        Event::None
    );
    for seq in 0..=127u8 {
        let start = 57 + usize::from(seq) * 59;
        let end = (start + 59).min(7609);
        let event = transport.receive(&cont_packet(1, seq, &data[start..end]), 0);
        assert_eq!(event, Event::None, "seq {seq}");
    }
    let reports = drain(&mut transport, 0);
    assert_eq!(reports.len(), 129);
    assert_eq!(reports[128][4], 0x7F);
    assert_eq!(messages(&reports), vec![(1, 0x01, data)]);
}

/// BCNT above the device buffer is ERR_INVALID_LEN at the initialization packet, so nothing is
/// buffered for it; BCNT equal to the buffer is accepted.
#[test]
fn length_above_the_buffer_is_invalid_len() {
    let mut transport = with_channels::<100>(1);
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x10, 101, &[0; 57]), 0),
        error(1, 0x03)
    );
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x10, 0xFFFF, &[0; 57]), 0),
        error(1, 0x03)
    );
    assert_eq!(
        exchange(&mut transport, &init_packet(1, 0x10, 100, &[0; 57]), 0),
        (Event::None, vec![])
    );
}

/// MSG and CBOR requests go to the CTAP layer; until they are answered the device sends
/// ERR_CHANNEL_BUSY to other channels and to new requests on the same channel (§11.2.5.1). The
/// answer carries the request's command on the request's channel.
#[test]
fn a_request_keeps_the_device_busy_until_answered() {
    let mut transport = with_channels::<1024>(2);
    let (event, replies) = exchange(
        &mut transport,
        &init_packet(1, 0x03, 3, &[0x00, 0x03, 0x00]),
        0,
    );
    assert_eq!(
        (event, replies),
        (
            Event::Request {
                cid: 1,
                command: Command::Msg
            },
            vec![]
        )
    );
    assert_eq!(transport.active(), Some(1));
    assert_eq!(transport.request(), Some(&[0x00, 0x03, 0x00][..]));
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 0),
        error(2, 0x06)
    );
    let broadcast_init = init_packet(BROADCAST_CID, 0x06, 8, &NONCE);
    assert_eq!(
        answer(&mut transport, &broadcast_init, 0),
        error(BROADCAST_CID, 0x06)
    );
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x01, 0, &[]), 0),
        error(1, 0x06)
    );
    assert_eq!(
        exchange(&mut transport, &cont_packet(2, 0, &[]), 0),
        (Event::None, vec![])
    );
    assert_eq!(transport.respond(&[0x90, 0x00], 0), Ok(()));
    assert_eq!(transport.active(), None);
    assert_eq!(transport.request(), None);
    assert_eq!(sent(&mut transport, 0), vec![(1, 0x03, vec![0x90, 0x00])]);
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 0),
        (2, 0x01, Vec::new())
    );
}

/// A CBOR answer goes out as CTAPHID_CBOR on the request's channel, split into packets like any
/// message (§11.2.9.1.2).
#[test]
fn a_cbor_answer_is_framed_on_its_channel() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1, 0);
    let response: Vec<u8> = (0..100u8).collect();
    assert_eq!(transport.respond(&response, 0), Ok(()));
    assert_eq!(sent(&mut transport, 0), vec![(1, 0x10, response)]);
}

/// The device is busy until the last report of a response has been handed out, not only until
/// the response exists: while a long echo is still being sent, another channel gets
/// ERR_CHANNEL_BUSY, ahead of the rest of the echo (§11.2.5.1).
#[test]
fn the_device_is_busy_until_the_response_is_sent() {
    let mut transport = with_channels::<1024>(2);
    let data = [0x42u8; 57];
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 116, &data), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0x42; 59]), 0),
        Event::None
    );
    let first = take(&mut transport, 0).expect("the first report of the echo");
    assert_eq!(first[4], 0x81);
    transport.sent();
    assert_eq!(
        transport.receive(&init_packet(2, 0x01, 0, &[]), 0),
        Event::None
    );
    let reports = drain(&mut transport, 0);
    assert_eq!(
        messages(&reports[..1]),
        vec![error(2, 0x06)],
        "the busy error goes first"
    );
    assert_eq!(
        messages(&[&[first][..], &reports[1..]].concat()),
        vec![(1, 0x01, vec![0x42; 116])]
    );
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 0),
        (2, 0x01, Vec::new()),
        "idle once the echo is out"
    );
}

/// Looking at the next report does not consume it: a device whose stack refuses the report asks
/// again and gets the same one, so a response never loses a packet. Once its transaction is
/// aborted, the next look gives the answer that replaced it, never a stale packet.
#[test]
fn a_report_is_consumed_only_once_taken() {
    let mut transport = with_channels::<1024>(1);
    transport.receive(&init_packet(1, 0x01, 116, &[7; 57]), 0);
    transport.receive(&cont_packet(1, 0, &[7; 59]), 0);
    let first = transport
        .next_report()
        .expect("the first report of the echo");
    assert_eq!(
        transport.next_report(),
        Some(first),
        "not taken, so offered again"
    );
    transport.receive(&init_packet(1, 0x06, 8, &NONCE), 0);
    let replaced = transport.next_report().expect("the INIT response");
    assert_eq!(replaced[4], 0x86, "the aborted echo is gone");
}

/// The busy period ends when the host has read the last report of a response, not when the
/// device handed it to the endpoint (§11.2.5.1): until `sent` acknowledges that completion,
/// another channel is still busy, and nothing else is offered while the endpoint holds a report.
#[test]
fn the_device_is_busy_until_the_last_report_is_read() {
    let mut transport = with_channels::<1024>(2);
    transport.receive(&init_packet(1, 0x01, 1, &[0x42]), 0);
    let echo = take(&mut transport, 0).expect("the one-report echo");
    assert_eq!(messages(&[echo]), vec![(1, 0x01, vec![0x42])]);
    assert_eq!(
        transport.receive(&init_packet(2, 0x01, 0, &[]), 0),
        Event::None
    );
    assert_eq!(transport.next_report(), None, "the echo is in the endpoint");
    transport.sent();
    assert_eq!(
        sent(&mut transport, 0),
        vec![error(2, 0x06)],
        "busy while the echo was unread"
    );
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 0),
        (2, 0x01, Vec::new()),
        "idle once the echo was read"
    );
}

/// A busy error for the channel whose response is being sent waits until that response is out:
/// an initialization packet in the middle of the channel's own message would break the host's
/// reassembly (§11.2.4). Errors for other channels still go first.
#[test]
fn a_busy_error_does_not_split_the_channels_own_response() {
    let mut transport = with_channels::<1024>(2);
    transport.receive(&init_packet(1, 0x01, 116, &[9; 57]), 0);
    transport.receive(&cont_packet(1, 0, &[9; 59]), 0);
    let first = take(&mut transport, 0).expect("the first report of the echo");
    transport.sent();
    transport.receive(&init_packet(1, 0x01, 0, &[]), 0);
    transport.receive(&init_packet(2, 0x01, 0, &[]), 0);
    let rest = drain(&mut transport, 0);
    assert_eq!(
        messages(&[&[first][..], &rest].concat()),
        vec![error(2, 0x06), (1, 0x01, vec![9; 116]), error(1, 0x06)]
    );
}

/// A restart (the device was reset on the bus) forgets every channel, transaction and queued
/// report and wipes the buffer: channels are allocated from 1 again and nothing stale is sent.
#[test]
fn a_restart_forgets_channels_and_transactions() {
    let mut transport = with_channels::<1024>(3);
    transport.receive(&init_packet(1, 0x01, 116, &[7; 57]), 0);
    transport.receive(&cont_packet(1, 0, &[7; 59]), 0);
    transport.receive(&init_packet(9, 0x01, 0, &[]), 0);
    transport.restart();
    assert_eq!(transport.next_report(), None, "nothing stale is sent");
    assert!(transport.buffer.iter().all(|&byte| byte == 0));
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 0),
        error(2, 0x0B),
        "channel 2 is no longer allocated"
    );
    let (_, _, payload) = answer(
        &mut transport,
        &init_packet(BROADCAST_CID, 0x06, 8, &NONCE),
        0,
    );
    assert_eq!(payload[8..12], [0, 0, 0, 1]);
}

/// INIT on the channel whose response is being sent aborts it: the rest of the response is
/// dropped and the INIT response follows (§11.2.5.3). CANCEL there is ignored: the answer is
/// already on its way (§11.2.9.1.5).
#[test]
fn init_aborts_a_response_being_sent() {
    let mut transport = with_channels::<1024>(1);
    transport.receive(&init_packet(1, 0x01, 116, &[7; 57]), 0);
    transport.receive(&cont_packet(1, 0, &[7; 59]), 0);
    take(&mut transport, 0).expect("the first report of the echo");
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 0, &[]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x06, 8, &NONCE), 0),
        Event::None
    );
    // The report already in the endpoint is read before anything else goes.
    assert_eq!(transport.next_report(), None);
    transport.sent();
    let (cid, command, payload) = sent(&mut transport, 0).remove(0);
    assert_eq!(
        (cid, command, &payload[8..12]),
        (1, 0x06, &[0, 0, 0, 1][..])
    );
    assert_eq!(transport.next_report(), None);
}

/// A response whose next report the device's stack stops taking is dropped after the packet
/// timeout, so the device does not stay busy for good; until then it is kept.
#[test]
fn a_response_the_host_stops_reading_is_dropped() {
    let mut transport = with_channels::<1024>(2);
    transport.receive(&init_packet(1, 0x01, 116, &[7; 57]), 0);
    transport.receive(&cont_packet(1, 0, &[7; 59]), 0);
    take(&mut transport, 100).expect("the first report of the echo");
    transport.sent();
    let just_in_time = 100 + PACKET_TIMEOUT_MS - 1;
    transport.poll(just_in_time);
    assert_eq!(
        transport.receive(&init_packet(2, 0x01, 0, &[]), just_in_time),
        Event::None
    );
    let busy = take(&mut transport, just_in_time).expect("the busy error comes first");
    assert_eq!(messages(&[busy]), vec![error(2, 0x06)], "still sending");
    transport.sent();
    // The rest of the echo is never taken.
    transport.poll(100 + PACKET_TIMEOUT_MS);
    assert_eq!(transport.next_report(), None);
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 1000),
        (2, 0x01, Vec::new())
    );
}

/// An answer for a request INIT aborted, or for no request at all, is refused and nothing is
/// sent; an answer longer than the buffer is refused and leaves the request waiting, so the CTAP
/// layer can still answer it.
#[test]
fn respond_refuses_a_missing_request_and_an_oversized_answer() {
    let mut transport = with_channels::<100>(1);
    assert_eq!(transport.respond(&[0], 0), Err(RespondError::NotActive));
    cbor_request(&mut transport, 1, 0);
    assert_eq!(transport.respond(&[0; 101], 0), Err(RespondError::TooLong));
    assert_eq!(transport.active(), Some(1));
    answer(&mut transport, &init_packet(1, 0x06, 8, &NONCE), 0);
    assert_eq!(transport.respond(&[0], 0), Err(RespondError::NotActive));
    assert_eq!(transport.next_report(), None);
}

/// While a request is processed the device sends a keepalive at least every 100 ms
/// (§11.2.9.1.7): a poll on a 100 ms timer schedules one on every tick, polls closer together do
/// not flood the host, a status change is reported at once, and the answer ends them.
#[test]
fn keepalives_follow_the_processing_request() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1, 1000);
    transport.poll(1010);
    assert_eq!(transport.next_report(), None, "too soon");
    let mut processing = [0u8; 64];
    processing[..8].copy_from_slice(&[0, 0, 0, 1, 0xBB, 0x00, 0x01, 0x01]);
    for tick in 1..=3 {
        let now = 1000 + tick * KEEPALIVE_INTERVAL_MS;
        transport.poll(now);
        assert_eq!(drain(&mut transport, now), vec![processing], "tick {tick}");
    }
    transport.set_status(KeepaliveStatus::UpNeeded);
    let mut up_needed = processing;
    up_needed[7] = 0x02;
    assert_eq!(drain(&mut transport, 1310), vec![up_needed]);
    transport.set_status(KeepaliveStatus::UpNeeded);
    assert_eq!(transport.next_report(), None, "no change, no keepalive");
    transport.poll(1400);
    assert_eq!(drain(&mut transport, 1400), vec![up_needed]);
    transport.poll(1500);
    assert_eq!(transport.respond(&[0x00], 1500), Ok(()));
    assert_eq!(sent(&mut transport, 1500), vec![(1, 0x10, vec![0x00])]);
    transport.poll(1600);
    assert_eq!(transport.next_report(), None);
}

/// Errors wait for the endpoint in order; a host that sends faster than it reads loses the
/// errors beyond the queue, not the device's state.
#[test]
fn queued_errors_keep_their_order_and_overflow_is_dropped() {
    let mut transport = with_channels::<1024>(1);
    for cid in 10..16 {
        assert_eq!(
            transport.receive(&init_packet(cid, 0x01, 0, &[]), 0),
            Event::None
        );
    }
    assert_eq!(
        sent(&mut transport, 0),
        (10..14).map(|cid| error(cid, 0x0B)).collect::<Vec<_>>()
    );
}

/// A full error queue asks the device to stop taking reports, so a host that sends faster than it
/// reads is held back instead of losing the errors it is owed; reading frees the queue again.
#[test]
fn a_full_error_queue_holds_reports_back() {
    let mut transport = with_channels::<1024>(1);
    for cid in 10..13 {
        transport.receive(&init_packet(cid, 0x01, 0, &[]), 0);
        assert!(transport.can_receive(), "{} errors queued", cid - 9);
    }
    transport.receive(&init_packet(13, 0x01, 0, &[]), 0);
    assert!(!transport.can_receive(), "the fourth error fills the queue");
    take(&mut transport, 0).expect("the oldest error");
    assert!(transport.can_receive());
}

/// CANCEL on the active channel reaches the CTAP layer and is never answered; CANCEL anywhere
/// else, including an invalid channel, is ignored (§11.2.9.1.5).
#[test]
fn cancel_reaches_only_the_active_request() {
    let mut transport = with_channels::<1024>(2);
    for packet in [init_packet(1, 0x11, 0, &[]), init_packet(0, 0x11, 0, &[])] {
        assert_eq!(exchange(&mut transport, &packet, 0), (Event::None, vec![]));
    }
    cbor_request(&mut transport, 1, 0);
    assert_eq!(
        exchange(&mut transport, &init_packet(2, 0x11, 0, &[]), 0),
        (Event::None, vec![])
    );
    assert_eq!(
        exchange(&mut transport, &init_packet(1, 0x11, 0, &[]), 0),
        (Event::Cancel { cid: 1 }, vec![])
    );
    assert_eq!(transport.active(), Some(1), "the CTAP layer still answers");
}

/// Sends a PING of `payload` on channel 1 of `transport`, packet by packet.
fn ping_request<const N: usize>(transport: &mut Transport<N>, payload: &[u8], now: u64) {
    let bcnt = u16::try_from(payload.len()).expect("a test payload fits BCNT");
    let first = payload.len().min(57);
    transport.receive(&init_packet(1, 0x01, bcnt, &payload[..first]), now);
    for (seq, chunk) in payload[first..].chunks(59).enumerate() {
        let seq = u8::try_from(seq).expect("a test payload fits the sequence numbers");
        transport.receive(&cont_packet(1, seq, chunk), now);
    }
}

/// A client that keeps sending requests on another channel while a response is out gets
/// ERR_CHANNEL_BUSY each time (§11.2.5.1), but those errors cannot starve the response: after
/// an error the next report is the response's own, so it completes while the errors keep
/// flowing.
#[test]
fn busy_errors_do_not_starve_the_response() {
    let mut transport = with_channels::<1024>(2);
    let payload: Vec<u8> = (0..1000u16).map(|i| (i % 251) as u8).collect();
    ping_request(&mut transport, &payload, 0);
    let mut reports = Vec::new();
    for _ in 0..60 {
        // Busy while the echo is out; once it is, one of these becomes the active request.
        transport.receive(&init_packet(2, 0x10, 1, &[0x04]), 0);
        if let Some(report) = take(&mut transport, 0) {
            transport.sent();
            reports.push(report);
        }
    }
    // Read while the requests still come: 17 reports of echo among 60.
    let received = messages(&reports);
    assert!(
        received.contains(&(1, 0x01, payload)),
        "the PING echo arrived whole during the flood"
    );
    assert!(
        received.contains(&error(2, 0x06)),
        "the busy channel was told so"
    );
}

/// The same flood cannot starve the keepalives of a request being processed either: a due
/// keepalive goes right after an error, so the active channel still hears from the device at
/// least every 100 ms (§11.2.9.1.7).
#[test]
fn busy_errors_do_not_starve_keepalives() {
    let mut transport = with_channels::<1024>(2);
    cbor_request(&mut transport, 1, 0);
    let mut reports = Vec::new();
    for step in 1..=20u64 {
        let now = step * 50;
        transport.receive(&init_packet(2, 0x10, 1, &[0x04]), now);
        transport.poll(now);
        if let Some(report) = take(&mut transport, now) {
            transport.sent();
            reports.push(report);
        }
    }
    let keepalives = messages(&reports)
        .into_iter()
        .filter(|message| *message == (1, 0x3B, vec![1]))
        .count();
    // One is due every 100 ms over the second the flood lasts.
    assert!(keepalives >= 9, "{keepalives} keepalives in one second");
}

/// A report already handed to the IN endpoint cannot be taken back. When the host stops
/// reading, the rest of the response is dropped, but the device stays busy (§11.2.5.1) until
/// that report is read, so the stale report never precedes another transaction's answer.
#[test]
fn a_report_in_the_endpoint_keeps_the_device_busy_past_the_timeout() {
    let mut transport = with_channels::<1024>(2);
    ping_request(&mut transport, &[7; 100], 0);
    let first = take(&mut transport, 0).expect("the first report of the echo");
    assert_eq!(first[..7], [0, 0, 0, 1, 0x81, 0, 100]);
    assert_eq!(
        transport.next_report(),
        None,
        "nothing else while the endpoint holds a report"
    );
    transport.poll(PACKET_TIMEOUT_MS);
    assert_eq!(
        transport.receive(&init_packet(2, 0x10, 1, &[0x04]), PACKET_TIMEOUT_MS),
        Event::None,
        "still busy"
    );
    transport.sent();
    assert_eq!(
        sent(&mut transport, PACKET_TIMEOUT_MS),
        vec![error(2, 0x06)],
        "the rest of the echo is dropped, the busy answer goes"
    );
    cbor_request(&mut transport, 2, PACKET_TIMEOUT_MS);
}

/// CANCEL acts only on a CBOR request being processed and is ignored otherwise (§11.2.9.1.5): in
/// the middle of a message on the same channel it is not answered and leaves the message
/// assembling, so the rest of the message still makes the request.
#[test]
fn cancel_during_assembly_is_ignored() {
    let mut transport = with_channels::<1024>(1);
    for report in [
        init_packet(1, 0x10, 100, &[0; 57]),
        init_packet(1, 0x11, 0, &[]),
    ] {
        assert_eq!(exchange(&mut transport, &report, 0), (Event::None, vec![]));
    }
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 43]), 0),
        (
            Event::Request {
                cid: 1,
                command: Command::Cbor
            },
            vec![]
        )
    );
    assert_eq!(transport.request().map(<[u8]>::len), Some(100));
}

/// INIT on the channel whose request is being processed aborts that transaction: the request is
/// no longer active and the channel is confirmed (§11.2.5.3).
#[test]
fn init_on_the_processing_channel_aborts_its_request() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1, 0);
    let (cid, command, payload) = answer(&mut transport, &init_packet(1, 0x06, 8, &NONCE), 0);
    assert_eq!(
        (cid, command, &payload[8..12]),
        (1, 0x06, &[0, 0, 0, 1][..])
    );
    assert_eq!(transport.active(), None);
}

/// A continuation packet with the wrong sequence number, or an initialization packet other
/// than INIT in the middle of a message, is ERR_INVALID_SEQ and drops the message (§11.2.5.4).
#[test]
fn sequence_errors_drop_the_message() {
    let mut transport = with_channels::<1024>(1);
    let start = init_packet(1, 0x01, 100, &[0; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 1, &[0; 43]), 0),
        error(1, 0x04)
    );
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 43]), 0),
        (Event::None, vec![]),
        "the message is gone: its continuation is now spurious"
    );

    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x01, 0, &[]), 0),
        error(1, 0x04)
    );
}

/// INIT in the middle of a message on the same channel resynchronizes instead of failing
/// (§11.2.5.3).
#[test]
fn init_resynchronizes_a_message_in_progress() {
    let mut transport = with_channels::<1024>(1);
    let start = init_packet(1, 0x01, 100, &[0; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    let (cid, command, _) = answer(&mut transport, &init_packet(1, 0x06, 8, &NONCE), 0);
    assert_eq!((cid, command), (1, 0x06));
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 43]), 0),
        (Event::None, vec![])
    );
}

/// Another channel's request while a message is assembled gets ERR_CHANNEL_BUSY and the
/// message still completes (§11.2.5.1).
#[test]
fn another_channel_is_busy_while_a_message_is_assembled() {
    let mut transport = with_channels::<1024>(2);
    let start = init_packet(1, 0x01, 60, &[7; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        answer(&mut transport, &init_packet(2, 0x01, 0, &[]), 1),
        error(2, 0x06)
    );
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 0, &[7; 3]), 2),
        (1, 0x01, vec![7; 60])
    );
}

/// Continuation packets without a message in progress are ignored (§11.2.5.4).
#[test]
fn spurious_continuation_packets_are_ignored() {
    let mut transport = with_channels::<1024>(1);
    for seq in [0, 5, 0x7F] {
        assert_eq!(
            exchange(&mut transport, &cont_packet(1, seq, &[1; 59]), 0),
            (Event::None, vec![])
        );
    }
}

/// A message whose next packet is late is abandoned: the late continuation gets
/// ERR_MSG_TIMEOUT, a packet just in time continues it, and a clock that went backwards counts
/// as late (§11.2.5.2).
#[test]
fn a_late_packet_times_the_message_out() {
    let mut transport = with_channels::<1024>(1);
    let start = init_packet(1, 0x01, 200, &[0; 57]);
    assert_eq!(
        exchange(&mut transport, &start, 1000),
        (Event::None, vec![])
    );
    let just_in_time = 1000 + PACKET_TIMEOUT_MS - 1;
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 59]), just_in_time),
        (Event::None, vec![])
    );
    // Exactly the timeout after the previous packet is already late.
    assert_eq!(
        answer(
            &mut transport,
            &cont_packet(1, 1, &[0; 59]),
            just_in_time + PACKET_TIMEOUT_MS
        ),
        error(1, 0x05)
    );

    assert_eq!(
        exchange(&mut transport, &start, 5000),
        (Event::None, vec![])
    );
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 0, &[0; 59]), 4999),
        error(1, 0x05)
    );
}

/// The default timeout is 500 ms, so a continuation delayed by host scheduling for a few hundred
/// milliseconds still completes its message (§11.2.5.2).
#[test]
fn the_default_packet_timeout_is_500_ms() {
    let mut transport = with_channels::<1024>(1);
    let start = init_packet(1, 0x01, 200, &[0; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 59]), 499),
        (Event::None, vec![])
    );
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 1, &[0; 59]), 999),
        error(1, 0x05)
    );
}

/// A timeout set by the device replaces the default, for late packets and for polling alike.
#[test]
fn a_configured_packet_timeout_is_used() {
    let timeout = NonZeroU64::new(40).expect("non-zero");
    let mut transport = Transport::<1024>::new(INFO, [0; 1024]).with_packet_timeout(timeout);
    assert_eq!(transport.packet_timeout_ms(), 40);
    answer(
        &mut transport,
        &init_packet(BROADCAST_CID, 0x06, 8, &NONCE),
        0,
    );
    let start = init_packet(1, 0x01, 200, &[0; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 59]), 39),
        (Event::None, vec![])
    );
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 1, &[0; 59]), 79),
        error(1, 0x05)
    );

    assert_eq!(exchange(&mut transport, &start, 100), (Event::None, vec![]));
    transport.poll(139);
    assert_eq!(sent(&mut transport, 139), vec![]);
    transport.poll(140);
    assert_eq!(sent(&mut transport, 140), vec![error(1, 0x05)]);
}

/// After a timeout the device is idle again: another channel's request is served, not refused
/// as busy (§11.2.5.2).
#[test]
fn a_timed_out_message_frees_the_device() {
    let mut transport = with_channels::<1024>(2);
    let start = init_packet(1, 0x01, 200, &[0; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    let (event, replies) = exchange(
        &mut transport,
        &init_packet(2, 0x01, 0, &[]),
        PACKET_TIMEOUT_MS,
    );
    assert_eq!(event, Event::None);
    assert_eq!(replies, vec![(2, 0x01, Vec::new())]);
}

/// Unknown commands, the optional LOCK and WINK, and the response-only KEEPALIVE and ERROR are
/// ERR_INVALID_CMD (§11.2.9).
#[test]
fn unsupported_commands_are_invalid_cmd() {
    let mut transport = with_channels::<1024>(1);
    for cmd in [0x00, 0x02, 0x04, 0x08, 0x3B, 0x3F, 0x40, 0x7F] {
        assert_eq!(
            answer(&mut transport, &init_packet(1, cmd, 0, &[]), 0),
            error(1, 0x01),
            "command {cmd:#04x}"
        );
    }
}

/// Unused bytes SHOULD be zero but need not be (§11.2.4): padding is not payload.
#[test]
fn nonzero_padding_is_not_payload() {
    let mut transport = with_channels::<1024>(1);
    let mut packet = init_packet(1, 0x01, 2, &[0xAA, 0xBB]);
    packet[9..].fill(0xFF);
    assert_eq!(
        answer(&mut transport, &packet, 0),
        (1, 0x01, vec![0xAA, 0xBB])
    );
}

/// Command codes are the ones of §11.2.9; unknown codes come back as the error value.
#[test]
fn command_codes_follow_the_specification() {
    let table = [
        (0x01, Command::Ping),
        (0x03, Command::Msg),
        (0x04, Command::Lock),
        (0x06, Command::Init),
        (0x08, Command::Wink),
        (0x10, Command::Cbor),
        (0x11, Command::Cancel),
        (0x3B, Command::Keepalive),
        (0x3F, Command::Error),
    ];
    for (code, command) in table {
        assert_eq!(Command::try_from(code), Ok(command));
        assert_eq!(command as u8, code);
    }
    assert_eq!(Command::try_from(0x02), Err(UnknownCommand(0x02)));
    assert_eq!(ErrorCode::InvalidChannel as u8, 0x0B);
    assert_eq!(ErrorCode::LockRequired as u8, 0x0A);
}

/// An empty response is one initialization packet with BCNT 0 and zero padding (§11.2.4).
#[test]
fn an_empty_response_is_one_zero_padded_packet() {
    let mut transport = with_channels::<1024>(1);
    transport.receive(&init_packet(1, 0x01, 0, &[]), 0);
    let mut expected = [0u8; 64];
    expected[..7].copy_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x00]);
    assert_eq!(drain(&mut transport, 0), vec![expected]);
}

/// A response of exactly 57 bytes fits the initialization packet; 58 bytes need one
/// continuation packet carrying one byte (§11.2.4).
#[test]
fn responses_split_at_the_packet_boundaries() {
    for (len, packets) in [(57, 1), (58, 2), (116, 2), (117, 3)] {
        let mut transport = with_channels::<1024>(1);
        cbor_request(&mut transport, 1, 0);
        assert_eq!(transport.respond(&vec![0x5A; len], 0), Ok(()));
        let reports = drain(&mut transport, 0);
        assert_eq!(reports.len(), packets, "{len} bytes");
        assert_eq!(messages(&reports), vec![(1, 0x10, vec![0x5A; len])]);
    }
}

/// Message bytes (a request can carry PIN/UV material) leave the buffer when its transaction
/// ends: answered and sent, aborted by INIT, broken by a sequence error, timed out, echoed by
/// PING, or dropped because the host stopped reading.
#[test]
fn message_bytes_are_wiped_when_the_transaction_ends() {
    let secret = [0x5Au8; 57];
    let wiped = |transport: &Transport<1024>| transport.buffer.iter().all(|&byte| byte == 0);

    let mut answered = with_channels::<1024>(1);
    answered.receive(&init_packet(1, 0x10, 57, &secret), 0);
    assert_eq!(answered.respond(&[0x5A; 30], 0), Ok(()));
    assert_eq!(answered.buffer[30..57], [0; 27], "the request goes at once");
    drain(&mut answered, 0);
    assert!(wiped(&answered), "answered and sent");

    let mut aborted = with_channels::<1024>(1);
    aborted.receive(&init_packet(1, 0x10, 57, &secret), 0);
    aborted.receive(&init_packet(1, 0x06, 8, &NONCE), 0);
    drain(&mut aborted, 0);
    assert!(wiped(&aborted), "INIT abort");

    let mut broken = with_channels::<1024>(1);
    broken.receive(&init_packet(1, 0x10, 200, &secret), 0);
    broken.receive(&cont_packet(1, 3, &[0; 59]), 0);
    assert!(wiped(&broken), "sequence error");

    let mut stalled = with_channels::<1024>(1);
    stalled.receive(&init_packet(1, 0x10, 200, &secret), 0);
    stalled.poll(PACKET_TIMEOUT_MS);
    assert!(wiped(&stalled), "timeout");

    let mut echoed = with_channels::<1024>(1);
    echoed.receive(&init_packet(1, 0x01, 57, &secret), 0);
    drain(&mut echoed, 0);
    assert!(wiped(&echoed), "PING echo, once sent");

    let mut unread = with_channels::<1024>(1);
    unread.receive(&init_packet(1, 0x01, 100, &secret), 0);
    unread.receive(&cont_packet(1, 0, &secret[..43]), 0);
    take(&mut unread, 0);
    unread.poll(PACKET_TIMEOUT_MS);
    assert!(wiped(&unread), "response the host stopped reading");
}

/// An unknown command on channel 0, the broadcast channel or an unallocated channel is
/// ERR_INVALID_CHANNEL like any other command there: the channel is checked first (§11.2.3).
#[test]
fn unknown_commands_on_invalid_channels_are_invalid_channel() {
    let mut transport = with_channels::<1024>(1);
    for cid in [0, BROADCAST_CID, 5] {
        assert_eq!(
            answer(&mut transport, &init_packet(cid, 0x02, 0, &[]), 0),
            error(cid, 0x0B),
            "channel {cid:#x}"
        );
    }
}

/// A stalled message times out at its deadline without another report: polling gives the
/// channel ERR_MSG_TIMEOUT and frees the device (§11.2.5.2).
#[test]
fn polling_times_out_a_stalled_message() {
    let mut transport = with_channels::<1024>(1);
    let start = init_packet(1, 0x01, 200, &[0; 57]);
    assert_eq!(
        exchange(&mut transport, &start, 1000),
        (Event::None, vec![])
    );
    transport.poll(1000 + PACKET_TIMEOUT_MS - 1);
    assert_eq!(sent(&mut transport, 1000), vec![]);
    transport.poll(1000 + PACKET_TIMEOUT_MS);
    assert_eq!(sent(&mut transport, 1500), vec![error(1, 0x05)]);
    transport.poll(5000);
    assert_eq!(sent(&mut transport, 5000), vec![], "reported once");
    assert_eq!(
        exchange(&mut transport, &cont_packet(1, 0, &[0; 59]), 5000),
        (Event::None, vec![]),
        "its continuation is now spurious"
    );
}

/// INIT advertises exactly what the transport accepts (§11.2.9.1.3): CBOR only when enabled, MSG
/// only when enabled (NMSG otherwise), never WINK; a command not advertised is ERR_INVALID_CMD.
#[test]
fn advertised_capabilities_match_the_accepted_commands() {
    let cbor_only = DeviceInfo {
        version: [0, 1, 0],
        cbor: true,
        msg: false,
    };
    let mut transport = Transport::<1024>::new(cbor_only, [0; 1024]);
    let broadcast_init = init_packet(BROADCAST_CID, 0x06, 8, &NONCE);
    let (_, _, payload) = answer(&mut transport, &broadcast_init, 0);
    assert_eq!(payload[16], 0x04 | 0x08, "CBOR and NMSG, no WINK");
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x03, 1, &[0]), 0),
        error(1, 0x01)
    );
    cbor_request(&mut transport, 1, 0);

    let msg_only = DeviceInfo {
        version: [0, 1, 0],
        cbor: false,
        msg: true,
    };
    let mut transport = Transport::<1024>::new(msg_only, [0; 1024]);
    let (_, _, payload) = answer(&mut transport, &broadcast_init, 0);
    assert_eq!(payload[16], 0x00, "MSG only: no flag set");
    assert_eq!(
        answer(&mut transport, &init_packet(1, 0x10, 1, &[0x04]), 0),
        error(1, 0x01)
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x03, 1, &[0]), 0),
        Event::Request {
            cid: 1,
            command: Command::Msg
        }
    );
}

/// CANCEL is defined with BCNT 0 (§11.2.9.1.5): one with a payload cancels nothing, breaks no
/// message and, like every CANCEL, is not answered.
#[test]
fn cancel_with_a_payload_is_ignored() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1, 0);
    assert_eq!(
        exchange(&mut transport, &init_packet(1, 0x11, 1, &[0]), 0),
        (Event::None, vec![])
    );
    assert_eq!(transport.active(), Some(1));
    assert_eq!(transport.respond(&[0x00], 0), Ok(()));
    drain(&mut transport, 0);

    let start = init_packet(1, 0x01, 60, &[3; 57]);
    assert_eq!(exchange(&mut transport, &start, 0), (Event::None, vec![]));
    assert_eq!(
        exchange(&mut transport, &init_packet(1, 0x11, 2, &[0, 0]), 0),
        (Event::None, vec![])
    );
    assert_eq!(
        answer(&mut transport, &cont_packet(1, 0, &[3; 3]), 0),
        (1, 0x01, vec![3; 60])
    );
}

/// A CBOR request carries the CTAP command byte (§11.2.9.1.2) and a MSG request a U2F message
/// (§11.2.9.1.1), so BCNT 0 is no request: ERR_INVALID_LEN, nothing handed to the CTAP layer,
/// and the device stays idle for the next request.
#[test]
fn empty_cbor_and_msg_requests_are_invalid_length() {
    let mut transport = with_channels::<1024>(1);
    for command in [0x10, 0x03] {
        assert_eq!(
            answer(&mut transport, &init_packet(1, command, 0, &[]), 0),
            error(1, 0x03)
        );
        assert_eq!(transport.active(), None);
    }
    cbor_request(&mut transport, 1, 0);
}

/// A request refused while another transport runs gets an answer its own protocol reads as
/// "retry": the one CTAP2 status byte CTAP1_ERR_CHANNEL_BUSY (0x06, CTAP 2.2 §8.2) for CBOR, and
/// for MSG the two-byte status word SW_CONDITIONS_NOT_SATISFIED (0x6985), the U2F response a
/// platform retries (U2F raw messages §3.3); a one-byte answer is no U2F response at all.
#[test]
fn a_busy_refusal_answers_in_the_request_protocol() {
    assert_eq!(Command::Cbor.busy_answer(), [0x06]);
    assert_eq!(Command::Msg.busy_answer(), [0x69, 0x85]);
}

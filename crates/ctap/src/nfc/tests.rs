use super::*;

const SIZE: usize = 1024;

fn applet() -> Applet<SIZE> {
    Applet::new([0; SIZE])
}

fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Apdu<'_> {
    Apdu {
        cla,
        ins,
        p1,
        p2,
        data,
        ne: Some(SHORT_NE),
        extended: false,
    }
}

fn select(data: &[u8]) -> Apdu<'_> {
    apdu(0x00, 0xA4, 0x04, 0x00, data)
}

fn msg(data: &[u8]) -> Apdu<'_> {
    apdu(0x80, 0x10, 0x00, 0x00, data)
}

/// The answer to `apdu` as owned bytes and status word, or `None` for a request to run.
fn answer<const N: usize>(applet: &mut Applet<N>, apdu: &Apdu<'_>) -> Option<(Vec<u8>, u16)> {
    match applet.command(apdu) {
        Outcome::Reply(reply) | Outcome::Selected(reply) => Some((reply.data.to_vec(), reply.sw.0)),
        Outcome::Request => None,
    }
}

fn selected() -> Applet<SIZE> {
    let mut applet = applet();
    assert!(matches!(
        applet.command(&select(&AID)),
        Outcome::Selected(_)
    ));
    applet
}

/// A response of `len` bytes counting up, so every part read back can be placed.
fn response(len: usize) -> Vec<u8> {
    (0..len).map(|at| at as u8).collect()
}

/// §11.3.3: SELECT with the FIDO AID A0000006472F0001 answers the version string of a CTAP2-only
/// authenticator, "FIDO_2_0", with 9000, and counts as the tap.
#[test]
fn selecting_the_fido_aid_answers_its_version() {
    let mut applet = applet();
    let Outcome::Selected(reply) = applet.command(&select(&[0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1]))
    else {
        panic!("the FIDO AID selects the applet");
    };
    assert_eq!(reply.data, b"FIDO_2_0");
    assert_eq!(reply.sw, StatusWord(0x9000));
}

/// Readers select other applications first (an NDEF tag); an absent one is 6A82 (ISO/IEC 7816-4
/// 5.6) and selects nothing, so CTAP commands are still refused afterwards.
#[test]
fn another_aid_is_not_found() {
    let mut applet = applet();
    let ndef = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
    assert_eq!(answer(&mut applet, &select(&ndef)), Some((vec![], 0x6A82)));
    assert_eq!(answer(&mut applet, &msg(&[0x04])), Some((vec![], 0x6985)));
}

/// §11.3.3: the client selects the applet before any other command; until then CTAP commands
/// are refused (6985, conditions of use not satisfied).
#[test]
fn commands_wait_for_selection() {
    let mut applet = applet();
    assert_eq!(answer(&mut applet, &msg(&[0x04])), Some((vec![], 0x6985)));
}

/// SELECT by name has P1 04 and P2 00 (§11.3.3); other parameters are 6A86.
#[test]
fn select_parameters_are_checked() {
    let mut applet = applet();
    assert_eq!(
        answer(&mut applet, &apdu(0x00, 0xA4, 0x00, 0x00, &AID)),
        Some((vec![], 0x6A86))
    );
    assert_eq!(
        answer(&mut applet, &apdu(0x00, 0xA4, 0x04, 0x0C, &AID)),
        Some((vec![], 0x6A86))
    );
}

/// §11.3.5.1: NFCCTAP_MSG (80 10 00 00) carries the CTAP command byte and its CBOR; the request
/// is handed out whole and its response comes back with 9000.
#[test]
fn a_message_is_handed_out_and_answered() {
    let mut applet = selected();
    assert_eq!(answer(&mut applet, &msg(&[0x04])), None);
    assert_eq!(applet.request(), Some(&[0x04][..]));
    let reply = applet.respond(&[0x00, 0xA1, 0x01]).expect("unanswered");
    assert_eq!(reply.data, [0x00, 0xA1, 0x01]);
    assert_eq!(reply.sw, StatusWord::OK);
    assert_eq!(applet.request(), None);
}

/// §11.3.6, short encoding: a response longer than 256 bytes is chained (ISO/IEC 7816-4 5.3.4).
/// Each part carries at most Ne bytes and 61XX tells what is left, XX = 00 for 256 and more; GET
/// RESPONSE (in class 80 as in the §11.3.6 example, or 00) reads the next part.
#[test]
fn a_long_response_to_a_short_command_is_chained() {
    let mut applet = selected();
    applet.command(&msg(&[0x01]));
    let full = response(600);
    let first = applet.respond(&full).expect("unanswered");
    assert_eq!(first.data, &full[..256]);
    assert_eq!(first.sw, StatusWord(0x6100));
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0xC0, 0x00, 0x00, &[])),
        Some((full[256..512].to_vec(), 0x6158))
    );
    // The last 88 bytes, read with Le 58 as the platform was told.
    let last = Apdu {
        ne: Some(0x58),
        ..apdu(0x00, 0xC0, 0x00, 0x00, &[])
    };
    assert_eq!(
        answer(&mut applet, &last),
        Some((full[512..].to_vec(), 0x9000))
    );
    // Nothing is left to read.
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0xC0, 0x00, 0x00, &[])),
        Some((vec![], 0x6985))
    );
}

/// §11.3.6: a request in extended encoding gets an extended response, the whole of it at once.
#[test]
fn an_extended_command_gets_the_whole_response() {
    let mut applet = selected();
    let extended = Apdu {
        ne: Some(65_536),
        extended: true,
        ..msg(&[0x01])
    };
    applet.command(&extended);
    let full = response(1000);
    let reply = applet.respond(&full).expect("unanswered");
    assert_eq!(reply.data, &full[..]);
    assert_eq!(reply.sw, StatusWord::OK);
}

/// §11.3.6: a request that does not fit a short command is sent in parts with CLA 90, each
/// answered 9000, and ends with a part in CLA 80; the request is their concatenation. The parts
/// are those of the §11.3.6 example: 240 bytes, then 23.
#[test]
fn a_chained_request_is_assembled() {
    let mut applet = selected();
    let request = response(263);
    assert_eq!(
        answer(&mut applet, &apdu(0x90, 0x10, 0x00, 0x00, &request[..240])),
        Some((vec![], 0x9000))
    );
    assert_eq!(answer(&mut applet, &msg(&request[240..])), None);
    assert_eq!(applet.request(), Some(&request[..]));
}

/// A chained request longer than the buffer cannot be held: it is answered with the CTAP status
/// CTAP2_ERR_REQUEST_TOO_LARGE (0x39, CTAP 2.2 §8.2) under 9000, and the chain is dropped.
#[test]
fn a_request_beyond_the_buffer_is_too_large() {
    let mut applet = selected();
    let part = [0x41; 255];
    for _ in 0..4 {
        assert_eq!(
            answer(&mut applet, &apdu(0x90, 0x10, 0x00, 0x00, &part)),
            Some((vec![], 0x9000))
        );
    }
    // 1020 bytes so far; five more go past 1024.
    assert_eq!(
        answer(&mut applet, &msg(&[0x41; 5])),
        Some((vec![0x39], 0x9000))
    );
    // The chain is gone: a new message starts on its own.
    assert_eq!(answer(&mut applet, &msg(&[0x04])), None);
    assert_eq!(applet.request(), Some(&[0x04][..]));
}

/// A chain is a run of consecutive commands (ISO/IEC 7816-4 5.4.2): another command drops what was
/// assembled, so the next message is not prefixed with it.
#[test]
fn an_interrupted_chain_is_dropped() {
    let mut applet = selected();
    applet.command(&apdu(0x90, 0x10, 0x00, 0x00, &[0x01, 0x02]));
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x55, 0x00, 0x00, &[])),
        Some((vec![], 0x6D00))
    );
    applet.command(&msg(&[0x04]));
    assert_eq!(applet.request(), Some(&[0x04][..]));
}

/// A GET RESPONSE or an NFCCTAP_GETRESPONSE between the parts of a chain also ends it (ISO/IEC
/// 7816-4 5.4.2): the part after it starts a request of its own instead of finishing the old one.
#[test]
fn a_poll_inside_a_chain_drops_it() {
    for poll in [
        apdu(0x80, 0xC0, 0x00, 0x00, &[]),
        apdu(0x00, 0xC0, 0x00, 0x00, &[]),
        apdu(0x80, 0x11, 0x00, 0x00, &[]),
    ] {
        let mut applet = selected();
        applet.command(&apdu(0x90, 0x10, 0x00, 0x00, &[0x01, 0x02]));
        assert_eq!(
            answer(&mut applet, &poll),
            Some((vec![], 0x6985)),
            "{poll:?}"
        );
        applet.command(&msg(&[0x04]));
        assert_eq!(applet.request(), Some(&[0x04][..]), "{poll:?}");
    }
}

/// §11.3.7.2: P1 and P2 of NFCCTAP_GETRESPONSE are RFU and MUST be zero (P1 0x11 is taken as the
/// cancel platforms send). Other values are refused with 6A86, and the exchange stays where it
/// was: a waiting request is not cancelled, a ready response is not given out.
#[test]
fn getresponse_parameters_are_checked() {
    let mut applet = selected();
    applet.command(&apdu(0x80, 0x10, 0x80, 0x00, &[0x0B]));
    applet.wait_for_user(true);
    for (p1, p2) in [(0x01, 0x00), (0x00, 0x01), (0x11, 0x01)] {
        let bad = apdu(0x80, 0x11, p1, p2, &[]);
        assert_eq!(
            answer(&mut applet, &bad),
            Some((vec![], 0x6A86)),
            "{p1:02x} {p2:02x}"
        );
        assert!(!applet.cancelled(), "{p1:02x} {p2:02x}");
    }
    assert_eq!(applet.respond(&[0x00, 0x42]), None);
    let bad = apdu(0x80, 0x11, 0x00, 0x01, &[]);
    assert_eq!(answer(&mut applet, &bad), Some((vec![], 0x6A86)));
    let poll = apdu(0x80, 0x11, 0x00, 0x00, &[]);
    assert_eq!(answer(&mut applet, &poll), Some((vec![0x00, 0x42], 0x9000)));
}

/// §11.3.7.1: P1 bit 0x80 of NFCCTAP_MSG announces NFCCTAP_GETRESPONSE support; the other P1 bits
/// and P2 are RFU and MUST be zero, so they are refused with 6A86.
#[test]
fn message_parameters_are_checked() {
    let mut applet = selected();
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x10, 0x01, 0x00, &[0x04])),
        Some((vec![], 0x6A86))
    );
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x10, 0x00, 0x01, &[0x04])),
        Some((vec![], 0x6A86))
    );
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x10, 0x80, 0x00, &[0x04])),
        None
    );
}

/// §11.3.7: a client that set P1 0x80 gets 9100 with the status (2, user presence needed, as in
/// §11.2.9.1.7) once the request waits for the user, and polls NFCCTAP_GETRESPONSE; each poll
/// gets the current status until the response is ready, then the response with 9000.
#[test]
fn a_waiting_request_answers_status_updates() {
    let mut applet = selected();
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x10, 0x80, 0x00, &[0x0B])),
        None
    );
    let update = applet
        .wait_for_user(true)
        .expect("the message gets a status update");
    assert_eq!((update.data, update.sw), (&[0x02][..], StatusWord(0x9100)));
    let poll = apdu(0x80, 0x11, 0x00, 0x00, &[]);
    assert_eq!(answer(&mut applet, &poll), Some((vec![0x02], 0x9100)));
    // The user answered: processing again.
    assert_eq!(applet.wait_for_user(false), None);
    assert_eq!(answer(&mut applet, &poll), Some((vec![0x01], 0x9100)));
    assert_eq!(applet.respond(&[0x00]), None);
    assert_eq!(answer(&mut applet, &poll), Some((vec![0x00], 0x9000)));
    // The response was read once.
    assert_eq!(answer(&mut applet, &poll), Some((vec![], 0x6985)));
}

/// NFCCTAP_GETRESPONSE with P1 0x11 cancels the waiting request, as python-fido2 sends it: the
/// request ends like one cancelled over HID (§11.2.9.1.5), its response, CTAP2_ERR_KEEPALIVE_CANCEL,
/// still goes to the next poll, and the cancelling poll itself gets a status update.
#[test]
fn a_poll_can_cancel_the_request() {
    let mut applet = selected();
    applet.command(&apdu(0x80, 0x10, 0x80, 0x00, &[0x0B]));
    applet.wait_for_user(true);
    assert!(!applet.cancelled());
    let cancel = apdu(0x80, 0x11, 0x11, 0x00, &[]);
    assert_eq!(answer(&mut applet, &cancel), Some((vec![0x02], 0x9100)));
    assert!(applet.cancelled());
    assert_eq!(applet.respond(&[0x2D]), None);
    let poll = apdu(0x80, 0x11, 0x00, 0x00, &[]);
    assert_eq!(answer(&mut applet, &poll), Some((vec![0x2D], 0x9000)));
}

/// Without P1 0x80 the client cannot poll, so its NFCCTAP_MSG is answered with the response alone
/// (§11.3.7.1), however long the user takes.
#[test]
fn a_client_without_status_updates_waits_for_the_response() {
    let mut applet = selected();
    applet.command(&msg(&[0x0B]));
    assert_eq!(applet.wait_for_user(true), None);
    let reply = applet
        .respond(&[0x00])
        .expect("the message is still unanswered");
    assert_eq!((reply.data, reply.sw), (&[0x00][..], StatusWord::OK));
}

/// While a request runs, only NFCCTAP_GETRESPONSE, deselection and selection are taken: another
/// message is refused with 6985 and leaves the running request alone.
#[test]
fn one_request_runs_at_a_time() {
    let mut applet = selected();
    applet.command(&apdu(0x80, 0x10, 0x80, 0x00, &[0x0B]));
    applet.wait_for_user(true);
    assert_eq!(answer(&mut applet, &msg(&[0x04])), Some((vec![], 0x6985)));
    assert!(!applet.cancelled());
    assert_eq!(applet.request(), Some(&[0x0B][..]));
}

/// §11.3.4: NFCCTAP_CONTROL END CTAP_MSG (80 12 01 00) deselects the applet: answered 9000, and
/// CTAP commands are ignored until the next SELECT. A request running then is cancelled and its
/// response goes nowhere.
#[test]
fn deselection_ends_ctap() {
    let mut applet = selected();
    assert!(applet.selected());
    applet.command(&apdu(0x80, 0x10, 0x80, 0x00, &[0x0B]));
    applet.wait_for_user(true);
    let end = apdu(0x80, 0x12, 0x01, 0x00, &[]);
    assert_eq!(answer(&mut applet, &end), Some((vec![], 0x9000)));
    assert!(!applet.selected());
    assert!(applet.cancelled());
    assert_eq!(applet.respond(&[0x00]), None);
    assert_eq!(answer(&mut applet, &msg(&[0x04])), Some((vec![], 0x6985)));
    assert!(matches!(
        applet.command(&select(&AID)),
        Outcome::Selected(_)
    ));
    assert_eq!(answer(&mut applet, &msg(&[0x04])), None);
}

/// Selecting the applet again starts over (§11.3.3), cancelling a request that was running.
#[test]
fn reselection_cancels_a_running_request() {
    let mut applet = selected();
    applet.command(&msg(&[0x0B]));
    assert!(matches!(
        applet.command(&select(&AID)),
        Outcome::Selected(_)
    ));
    assert!(applet.cancelled());
    assert_eq!(applet.respond(&[0x00]), None);
}

/// A chained response is read in order or not at all: another command drops the rest, so GET
/// RESPONSE has nothing to give afterwards.
#[test]
fn another_command_drops_a_chained_response() {
    let mut applet = selected();
    applet.command(&msg(&[0x01]));
    let full = response(400);
    assert_eq!(
        applet.respond(&full).map(|reply| reply.sw),
        Some(StatusWord::more(144))
    );
    assert_eq!(answer(&mut applet, &msg(&[0x04])), None);
    assert_eq!(
        applet.respond(&[0x00]).map(|reply| reply.sw),
        Some(StatusWord::OK)
    );
    assert_eq!(
        answer(&mut applet, &apdu(0x00, 0xC0, 0x00, 0x00, &[])),
        Some((vec![], 0x6985))
    );
}

/// Unknown instructions of a known class are 6D00, unknown classes 6E00 (ISO/IEC 7816-4 5.6).
#[test]
fn unknown_commands_are_refused() {
    let mut applet = selected();
    assert_eq!(
        answer(&mut applet, &apdu(0x80, 0x55, 0x00, 0x00, &[])),
        Some((vec![], 0x6D00))
    );
    assert_eq!(
        answer(&mut applet, &apdu(0xE0, 0x01, 0x00, 0x00, &[])),
        Some((vec![], 0x6E00))
    );
}

/// A request can carry PIN material: the buffer holds nothing of it once the applet is gone.
#[test]
fn the_buffer_is_wiped() {
    let mut buffer = [0u8; SIZE];
    {
        let mut applet = Applet::<SIZE, &mut [u8; SIZE]>::new(&mut buffer);
        applet.command(&select(&AID));
        applet.command(&apdu(0x90, 0x10, 0x00, 0x00, &[0x55; 200]));
        applet.command(&msg(&[0x55; 100]));
        applet.respond(&response(500));
    }
    assert!(buffer.iter().all(|&byte| byte == 0));
}

/// The last part of a response is wiped at the next command, after the device sent it.
#[test]
fn a_sent_response_is_wiped_at_the_next_command() {
    let mut buffer = [0u8; SIZE];
    let mut applet = Applet::<SIZE, &mut [u8; SIZE]>::new(&mut buffer);
    applet.command(&select(&AID));
    applet.command(&msg(&[0x55; 10]));
    applet.respond(&[0x66; 10]);
    applet.command(&apdu(0x80, 0x55, 0x00, 0x00, &[]));
    assert!(applet.bytes().iter().all(|&byte| byte == 0));
}

//! The NFC applet driven by arbitrary command APDUs and device actions, shared by the fuzz target
//! and the regression test of its corpus.
//!
//! The input is a script: each step is an APDU from the reader, or the device answering the
//! request it runs or starting to wait for the user. The rules that hold for any script: a CTAP
//! request comes only from NFCCTAP_MSG of a selected applet (CTAP 2.2 §11.3.3, §11.3.4), never
//! longer than the buffer; every answer carries a status word the applet defines and no more data
//! than the command accepts (ISO/IEC 7816-4 5.1); a status update carries one keepalive status
//! byte, only to a client that asked for them (§11.3.7); and the parts of a response, read in
//! order, are the response the device gave.

use structured_passkeys_ctap::nfc::{AID, Apdu, Applet, Outcome, StatusWord, VERSION};

const SIZE: usize = 1024;

/// Status words the applet answers with, besides 61XX.
const STATUS_WORDS: [u16; 8] = [
    0x9000, 0x9100, 0x6700, 0x6985, 0x6A82, 0x6A86, 0x6D00, 0x6E00,
];

/// What the script knows of the exchange, to check the applet against.
#[derive(Default)]
struct Model {
    /// The applet answered the FIDO AID and was not deselected since.
    selected: bool,
    /// A request is with the device.
    running: bool,
    /// The running request came with NFCCTAP_MSG P1 0x80.
    updates: bool,
    /// The response the device gave and how much of it was read.
    response: Vec<u8>,
    read: usize,
}

/// Takes `n` bytes from the script, or what is left.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = data.split_at(n.min(data.len()));
    *data = tail;
    head
}

fn byte(data: &mut &[u8]) -> Option<u8> {
    take(data, 1).first().copied()
}

/// Runs one script; panics on any broken rule.
pub fn run(mut data: &[u8]) {
    let mut applet = Applet::<SIZE>::new([0; SIZE]);
    let mut model = Model::default();
    while let Some(op) = byte(&mut data) {
        match op & 0x03 {
            0 => apdu(&mut applet, &mut model, &mut data, op),
            1 => {
                // The device answers the running request with `len` bytes.
                let len = usize::from(byte(&mut data).unwrap_or(0)) * 8;
                let response: Vec<u8> = (0..len).map(|at| at as u8 ^ op).collect();
                let reply = applet
                    .respond(&response)
                    .map(|reply| (reply.data.to_vec(), reply.sw));
                if model.running {
                    model.running = false;
                    model.response = response;
                    model.read = 0;
                    if let Some((part, sw)) = reply {
                        check_part(&mut model, &part, sw);
                    }
                } else {
                    assert!(reply.is_none(), "a response with no request is dropped");
                }
            }
            _ => {
                let waiting = op & 0x04 != 0;
                let update = applet
                    .wait_for_user(waiting)
                    .map(|reply| (reply.data.to_vec(), reply.sw));
                if let Some((status, sw)) = update {
                    assert!(
                        model.running && model.updates && waiting,
                        "an update only when asked for"
                    );
                    assert_eq!((status, sw), (vec![0x02], StatusWord::STATUS_UPDATE));
                }
            }
        }
    }
}

/// One part of the response: the next bytes of it, under 9000 when it is the last part.
fn check_part(model: &mut Model, part: &[u8], sw: StatusWord) {
    let end = model.read + part.len();
    assert_eq!(
        part,
        &model.response[model.read..end],
        "parts come in order"
    );
    model.read = end;
    if sw == StatusWord::OK {
        assert_eq!(end, model.response.len(), "9000 ends the response");
    } else {
        assert_eq!(sw.0 & 0xFF00, 0x6100, "a part before the end is 61XX");
    }
}

fn apdu(applet: &mut Applet<SIZE>, model: &mut Model, data: &mut &[u8], op: u8) {
    let header = take(data, 5);
    let [cla, ins, p1, p2, flags] = <[u8; 5]>::try_from(header).unwrap_or_default();
    let extended = flags & 0x01 != 0;
    let ne = (flags & 0x02 != 0).then(|| {
        let most = if extended { 65_536 } else { 256 };
        (usize::from(flags >> 2) * 37).clamp(1, most)
    });
    // Bit 2 of the step selects the FIDO AID as the data, so selection is reached often.
    let length = usize::from(byte(data).unwrap_or(0));
    let body = if op & 0x04 != 0 {
        &AID[..]
    } else {
        take(data, length)
    };
    let apdu = Apdu {
        cla,
        ins,
        p1,
        p2,
        data: body,
        ne,
        extended,
    };
    let most = ne.unwrap_or(if extended { 65_536 } else { 256 });
    let was_running = model.running;
    match applet.command(&apdu) {
        Outcome::Selected(reply) => {
            assert_eq!((reply.data, reply.sw), (&VERSION[..], StatusWord::OK));
            assert_eq!((cla, ins, p1, p2, body), (0x00, 0xA4, 0x04, 0x00, &AID[..]));
            model.selected = true;
            model.running = false;
            model.response.clear();
        }
        Outcome::Request => {
            assert!(model.selected, "no request before selection");
            assert!(!was_running, "one request at a time");
            assert_eq!(
                (cla, ins),
                (0x80, 0x10),
                "only NFCCTAP_MSG carries a request"
            );
            let request = applet.request().expect("the request is readable");
            assert!(request.len() <= SIZE);
            model.running = true;
            model.updates = p1 & 0x80 != 0;
            model.response.clear();
        }
        Outcome::Reply(reply) => {
            let (part, sw) = (reply.data.to_vec(), reply.sw);
            assert!(part.len() <= most, "no more data than Ne");
            assert!(
                STATUS_WORDS.contains(&sw.0) || sw.0 & 0xFF00 == 0x6100,
                "unknown status word {:#06x}",
                sw.0
            );
            if (cla, ins, p1) == (0x80, 0x12, 0x01) && p2 == 0 && model.selected {
                // §11.3.4: END CTAP_MSG has no data field; one with data ends nothing.
                if body.is_empty() {
                    assert_eq!(sw, StatusWord::OK);
                    model.selected = false;
                    model.running = false;
                } else {
                    assert_eq!(sw, StatusWord::WRONG_LENGTH);
                }
            }
            if !model.selected {
                assert!(part.is_empty(), "nothing is answered before selection");
            }
            if sw == StatusWord::STATUS_UPDATE {
                assert!(
                    model.running && model.updates,
                    "updates only to a client that asked"
                );
                assert!(
                    part == [0x01] || part == [0x02],
                    "one keepalive status byte"
                );
            } else if !model.running
                && !model.response.is_empty()
                && matches!((cla, ins), (0x00 | 0x80, 0xC0) | (0x80, 0x11))
                && (sw == StatusWord::OK || sw.0 & 0xFF00 == 0x6100)
            {
                check_part(model, &part, sw);
            } else if sw == StatusWord::OK && part == [0x39] {
                // A chain beyond the buffer: CTAP2_ERR_REQUEST_TOO_LARGE.
            } else if model.response.len() > model.read
                && !matches!((cla, ins), (0x00 | 0x80, 0xC0) | (0x80, 0x11))
            {
                // Another command dropped the rest of the response.
                model.response.clear();
                model.read = 0;
            }
        }
    }
}

//! CTAP2 canonical CBOR decoding driven by arbitrary bytes: the checks of the fuzz target.
//!
//! The decoder's verdict is compared with [`reference`], a separate reading of the rules written
//! without the decoder's code, in both directions: accepting a forbidden encoding and refusing a
//! canonical one both fail. Accepted inputs are further checked against properties the
//! encoding guarantees.

use structured_passkeys_ctap::cbor::{Decoder, Error, MAX_NESTING, validate};

/// Runs one input; panics on any broken property.
pub fn run(data: &[u8]) {
    let verdict = validate(data);
    assert_eq!(
        verdict.is_ok(),
        reference(data),
        "decoder {verdict:?} disagrees with the reference on {data:02x?}"
    );
    // Reading the input as a CTAP request map gives the same verdict whenever it is one.
    if data.first().is_some_and(|byte| byte >> 5 == 5) {
        let mut decoder = Decoder::new(data);
        let read = decoder
            .map(|entries| {
                while entries.next_key()?.is_some() {}
                Ok(())
            })
            .and_then(|()| decoder.finish());
        assert_eq!(read, verdict, "map reading and validation disagree");
    }
    if verdict.is_err() {
        return;
    }
    // One definite-length item ends exactly where its encoding ends: a byte more is trailing
    // data, a byte less is truncated.
    let mut longer = data.to_vec();
    longer.push(0x00);
    assert_eq!(
        validate(&longer),
        Err(Error::Malformed),
        "trailing byte accepted"
    );
    for end in 0..data.len() {
        assert!(
            validate(&data[..end]).is_err(),
            "prefix of {end} bytes accepted"
        );
    }
    // Every accepted input fits the nesting limit: wrapping it in more arrays than the limit
    // allows is refused.
    let mut wrapped = vec![0x81; usize::from(MAX_NESTING)];
    wrapped.extend_from_slice(data);
    let nested = data.first().is_some_and(|byte| matches!(byte >> 5, 4 | 5));
    if nested {
        assert_eq!(
            validate(&wrapped),
            Err(Error::TooDeep),
            "nesting limit not enforced"
        );
    }
}

/// Whether `data` is exactly one item in the CTAP2 canonical form (CTAP 2.2 §8 over RFC 8949
/// §3): shortest arguments, definite lengths, no tags, valid UTF-8 text, at most four levels of
/// maps and arrays, map keys strictly ordered by major type, then encoded length, then bytes.
pub fn reference(data: &[u8]) -> bool {
    let mut position = 0;
    reference_item(data, &mut position, 0) && position == data.len()
}

fn reference_take<'a>(data: &'a [u8], position: &mut usize, count: u64) -> Option<&'a [u8]> {
    let count = usize::try_from(count).ok()?;
    let end = position.checked_add(count)?;
    let taken = data.get(*position..end)?;
    *position = end;
    Some(taken)
}

fn reference_item(data: &[u8], position: &mut usize, depth: u8) -> bool {
    let Some([initial]) = reference_take(data, position, 1) else {
        return false;
    };
    let (major, info) = (initial >> 5, initial & 0x1F);
    if major == 6 {
        return false;
    }
    if major == 7 {
        return match info {
            0..=23 => true,
            24 => reference_take(data, position, 1).is_some_and(|value| value[0] >= 32),
            25 => reference_take(data, position, 2).is_some(),
            26 => reference_take(data, position, 4).is_some(),
            27 => reference_take(data, position, 8).is_some(),
            _ => false,
        };
    }
    let (width, smallest) = match info {
        0..=23 => (0, 0),
        24 => (1, 24),
        25 => (2, 1 << 8),
        26 => (4, 1 << 16),
        27 => (8, 1 << 32),
        _ => return false,
    };
    let Some(argument) = reference_take(data, position, width) else {
        return false;
    };
    let value = if width == 0 {
        u64::from(info)
    } else {
        argument
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
    };
    if value < smallest {
        return false;
    }
    match major {
        0 | 1 => true,
        2 => reference_take(data, position, value).is_some(),
        3 => reference_take(data, position, value)
            .is_some_and(|text| std::str::from_utf8(text).is_ok()),
        4 => {
            if depth >= 4 {
                return false;
            }
            let inner = depth
                .checked_add(1)
                .expect("depth is below 4, checked above");
            (0..value).all(|_| reference_item(data, position, inner))
        }
        _ => {
            if depth >= 4 {
                return false;
            }
            let inner = depth
                .checked_add(1)
                .expect("depth is below 4, checked above");
            let mut previous: Option<&[u8]> = None;
            for _ in 0..value {
                let start = *position;
                if !reference_item(data, position, inner) {
                    return false;
                }
                let key = &data[start..*position];
                if let Some(previous) = previous {
                    let order = (previous[0] >> 5, previous.len(), previous);
                    if order >= (key[0] >> 5, key.len(), key) {
                        return false;
                    }
                }
                previous = Some(key);
                if !reference_item(data, position, inner) {
                    return false;
                }
            }
            true
        }
    }
}

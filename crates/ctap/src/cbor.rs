//! The CTAP2 canonical CBOR encoding (CTAP 2.2, §8 "Message Encoding").
//!
//! [`Decoder`] reads a message in place: strings are borrowed from the input, nothing is
//! allocated, and every rule of the canonical form is checked while reading, including in values
//! that are skipped (§8: unknown map keys are ignored, but the message stays canonical).
//! [`Encoder`] writes the canonical form into a caller-provided buffer; map keys are written by
//! the caller in canonical order.
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::cbor::{Decoder, Encoder, Key};
//!
//! // {1: "a", 2: h'00'}
//! let mut buffer = [0u8; 16];
//! let mut encoder = Encoder::new(&mut buffer);
//! encoder.map(2)?.unsigned(1)?.text("a")?.unsigned(2)?.bytes(&[0])?;
//! let message = encoder.as_bytes();
//! assert_eq!(message, [0xA2, 0x01, 0x61, b'a', 0x02, 0x41, 0x00]);
//!
//! let mut decoder = Decoder::new(message);
//! let text = decoder.map(|entries| {
//!     let mut text = None;
//!     while let Some(key) = entries.next_key()? {
//!         if key == Key::Int(1) {
//!             text = Some(entries.value().text()?);
//!         }
//!     }
//!     Ok(text)
//! })?;
//! decoder.finish()?;
//! assert_eq!(text, Some("a"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use core::cmp::Ordering;
use core::fmt;

/// Most levels of maps and arrays a message may nest (§8).
pub const MAX_NESTING: u8 = 4;

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not well-formed CBOR (RFC 8949 §3): truncated, a reserved encoding, a tag (§8 forbids
    /// them), invalid UTF-8, or bytes after the message.
    Malformed,
    /// Well-formed but not canonical (§8): a longer encoding than the value needs, an
    /// indefinite length, or map keys out of order or repeated.
    NotCanonical,
    /// More than [`MAX_NESTING`] levels of maps and arrays (§8).
    TooDeep,
    /// A value of another type than the field requires.
    UnexpectedType,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Error::Malformed => "malformed CBOR",
            Error::NotCanonical => "CBOR not in the CTAP2 canonical form",
            Error::TooDeep => "CBOR nested too deeply",
            Error::UnexpectedType => "unexpected CBOR type",
        })
    }
}

impl core::error::Error for Error {}

/// CBOR major types (RFC 8949 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Major {
    Unsigned = 0,
    Negative = 1,
    Bytes = 2,
    Text = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Simple = 7,
}

impl Major {
    const fn from_initial(byte: u8) -> Self {
        match byte >> 5 {
            0 => Major::Unsigned,
            1 => Major::Negative,
            2 => Major::Bytes,
            3 => Major::Text,
            4 => Major::Array,
            5 => Major::Map,
            6 => Major::Tag,
            _ => Major::Simple,
        }
    }
}

/// Additional information values with a following argument (RFC 8949 §3).
const ONE_BYTE: u8 = 24;
const TWO_BYTES: u8 = 25;
const FOUR_BYTES: u8 = 26;
const EIGHT_BYTES: u8 = 27;
const INDEFINITE: u8 = 31;

/// Simple values: false, true, null (RFC 8949 §3.3).
const FALSE: u64 = 20;
const TRUE: u64 = 21;
const NULL: u64 = 22;

/// A map key as CTAP uses them: an integer or a text string. Other keys are well-formed but
/// never meaningful to CTAP and come back as [`Key::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key<'a> {
    /// An integer key that fits `i64`.
    Int(i64),
    /// A text key.
    Text(&'a str),
    /// Any other key.
    Other,
}

/// Reads one CTAP2 canonical CBOR message from a byte slice.
#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    /// Maps and arrays open around the next item.
    depth: u8,
}

impl<'a> Decoder<'a> {
    /// Starts reading `input`, which holds exactly one message.
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, depth: 0 }
    }

    /// Ends the message: bytes after it are malformed (§8, one data item per message).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when input remains.
    pub fn finish(self) -> Result<(), Error> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let Some((taken, rest)) = self.input.split_at_checked(count) else {
            return Err(Error::Malformed);
        };
        self.input = rest;
        Ok(taken)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let bytes = self.take(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    /// Reads an initial byte and its argument, checking the shortest-form rule (§8: integers
    /// and lengths as small as possible).
    fn head(&mut self) -> Result<(Major, u64), Error> {
        let [initial] = self.take_array::<1>()?;
        let major = Major::from_initial(initial);
        let info = initial & 0x1F;
        match major {
            // §8: tags MUST NOT be present, whatever the width of their number.
            Major::Tag => return Err(Error::Malformed),
            Major::Simple => return self.simple_head(info).map(|value| (major, value)),
            _ => {}
        }
        let (value, minimum) = match info {
            0..=23 => return Ok((major, u64::from(info))),
            ONE_BYTE => (u64::from(self.take_array::<1>()?[0]), 24),
            TWO_BYTES => (u64::from(u16::from_be_bytes(self.take_array()?)), 0x100),
            FOUR_BYTES => (u64::from(u32::from_be_bytes(self.take_array()?)), 0x1_0000),
            EIGHT_BYTES => (u64::from_be_bytes(self.take_array()?), 0x1_0000_0000),
            // §8: indefinite lengths are made definite; for other major types 31 is not
            // well-formed (RFC 8949 §3.2.4).
            INDEFINITE
                if matches!(
                    major,
                    Major::Bytes | Major::Text | Major::Array | Major::Map
                ) =>
            {
                return Err(Error::NotCanonical);
            }
            _ => return Err(Error::Malformed),
        };
        if value < minimum {
            return Err(Error::NotCanonical);
        }
        Ok((major, value))
    }

    /// Major type 7. Floats keep their encoded width (§8: their representation is not
    /// changed), so they carry no shortest-form rule; a one-byte simple value below 32 is not
    /// well-formed (RFC 8949 §3.3).
    fn simple_head(&mut self, info: u8) -> Result<u64, Error> {
        match info {
            0..=23 => Ok(u64::from(info)),
            ONE_BYTE => {
                let [value] = self.take_array::<1>()?;
                if value < 32 {
                    Err(Error::Malformed)
                } else {
                    Ok(u64::from(value))
                }
            }
            TWO_BYTES => self.take(2).map(|_| u64::MAX),
            FOUR_BYTES => self.take(4).map(|_| u64::MAX),
            EIGHT_BYTES => self.take(8).map(|_| u64::MAX),
            _ => Err(Error::Malformed),
        }
    }

    /// A length argument that must fit the remaining input, so no count from the message can
    /// exceed what was received.
    fn length(&self, value: u64, item_size: usize) -> Result<usize, Error> {
        let length = usize::try_from(value).map_err(|_| Error::Malformed)?;
        match length.checked_mul(item_size) {
            Some(needed) if needed <= self.input.len() => Ok(length),
            _ => Err(Error::Malformed),
        }
    }

    fn expect(&mut self, wanted: Major) -> Result<u64, Error> {
        let start = self.input;
        let (major, value) = self.head()?;
        if major == wanted {
            Ok(value)
        } else {
            Err(self.mismatch(start))
        }
    }

    /// The error for an item of the wrong type starting at `start`: the item is read in full
    /// first, so a malformed one stays an encoding error (§8: CBOR that does not conform is
    /// INVALID_CBOR, only a well-formed member of the wrong type is CBOR_UNEXPECTED_TYPE).
    fn mismatch(&mut self, start: &'a [u8]) -> Error {
        self.input = start;
        match self.skip() {
            Ok(()) => Error::UnexpectedType,
            Err(error) => error,
        }
    }

    /// Reads an unsigned integer.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for any other item, or the encoding errors of the item.
    pub fn unsigned(&mut self) -> Result<u64, Error> {
        self.expect(Major::Unsigned)
    }

    /// Reads an integer of either sign that fits `i64`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for a non-integer or one outside `i64`, or the encoding errors
    /// of the item.
    pub fn int(&mut self) -> Result<i64, Error> {
        let start = self.input;
        match self.head()? {
            (Major::Unsigned, value) => i64::try_from(value).map_err(|_| Error::UnexpectedType),
            // -1 - n; an argument whose value does not fit i64 is outside the range read here.
            (Major::Negative, value) => i64::try_from(value)
                .ok()
                .and_then(|n| (-1i64).checked_sub(n))
                .ok_or(Error::UnexpectedType),
            _ => Err(self.mismatch(start)),
        }
    }

    /// Reads a byte string, borrowed from the input.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for any other item, or the encoding errors of the item.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let value = self.expect(Major::Bytes)?;
        let length = self.length(value, 1)?;
        self.take(length)
    }

    /// Reads a text string, borrowed from the input.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid UTF-8, [`Error::UnexpectedType`] for any other item, or
    /// the encoding errors of the item.
    pub fn text(&mut self) -> Result<&'a str, Error> {
        let value = self.expect(Major::Text)?;
        let length = self.length(value, 1)?;
        core::str::from_utf8(self.take(length)?).map_err(|_| Error::Malformed)
    }

    /// Reads `true` or `false`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for any other item, or the encoding errors of the item.
    pub fn bool(&mut self) -> Result<bool, Error> {
        let start = self.input;
        match self.head()? {
            (Major::Simple, FALSE) => Ok(false),
            (Major::Simple, TRUE) => Ok(true),
            _ => Err(self.mismatch(start)),
        }
    }

    /// Opens a nested map or array; the depth is restored by [`Decoder::close`].
    fn open(&mut self) -> Result<(), Error> {
        if self.depth >= MAX_NESTING {
            return Err(Error::TooDeep);
        }
        self.depth = self
            .depth
            .checked_add(1)
            .expect("depth stays below MAX_NESTING, checked above");
        Ok(())
    }

    /// Every `close` follows a successful `open`, so the depth is at least one here.
    fn close(&mut self) {
        self.depth = self
            .depth
            .checked_sub(1)
            .expect("close matches a successful open");
    }

    /// Reads an array: `read` gets its elements and may stop early, the rest is skipped and
    /// still checked.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for any other item, [`Error::TooDeep`], the encoding errors of
    /// any element, or the error `read` returns.
    pub fn array<T>(
        &mut self,
        read: impl FnOnce(&mut Elements<'_, 'a>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let value = self.expect(Major::Array)?;
        let remaining = self.length(value, 1)?;
        self.open()?;
        let mut elements = Elements {
            decoder: self,
            remaining,
        };
        let result = read(&mut elements)?;
        while elements.next_element().is_some() {
            elements.decoder.skip()?;
        }
        self.close();
        Ok(result)
    }

    /// Reads a map: `read` walks its entries in order and may stop early, the rest is skipped
    /// and still checked, keys included.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedType`] for any other item, [`Error::TooDeep`], [`Error::NotCanonical`]
    /// for keys out of order or repeated, the encoding errors of any entry, or the error `read`
    /// returns.
    pub fn map<T>(
        &mut self,
        read: impl FnOnce(&mut Entries<'_, 'a>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let value = self.expect(Major::Map)?;
        let remaining = self.length(value, 2)?;
        self.open()?;
        let mut entries = Entries {
            decoder: self,
            remaining,
            previous: None,
            value_pending: false,
        };
        let result = read(&mut entries)?;
        while entries.next_key()?.is_some() {}
        self.close();
        Ok(result)
    }

    /// Skips one item of any type, checking it as thoroughly as if it were read.
    ///
    /// # Errors
    ///
    /// The encoding errors of the item or of anything nested in it.
    pub fn skip(&mut self) -> Result<(), Error> {
        let start = self.input;
        let (major, value) = self.head()?;
        match major {
            Major::Unsigned | Major::Negative | Major::Simple => Ok(()),
            Major::Bytes => {
                let length = self.length(value, 1)?;
                self.take(length).map(|_| ())
            }
            Major::Text => {
                let length = self.length(value, 1)?;
                core::str::from_utf8(self.take(length)?)
                    .map(|_| ())
                    .map_err(|_| Error::Malformed)
            }
            Major::Array | Major::Map => {
                // Rewind and read it as a container, so the nesting and key checks apply.
                self.input = start;
                if major == Major::Array {
                    self.array(|_| Ok(()))
                } else {
                    self.map(|_| Ok(()))
                }
            }
            // `head` refuses tags.
            Major::Tag => Err(Error::Malformed),
        }
    }

    /// Reads a whole item, checking it as [`Decoder::skip`] does, and returns its encoded bytes:
    /// for a member a MAC covers as received (CTAP 2.2 §6.8, `subCommandParams`).
    ///
    /// # Errors
    ///
    /// The encoding errors of the item or of anything nested in it.
    pub fn encoded_item(&mut self) -> Result<&'a [u8], Error> {
        let start = self.input;
        self.skip()?;
        let read = start
            .len()
            .checked_sub(self.input.len())
            .expect("reading only shortens the input");
        Ok(&start[..read])
    }
}

/// The elements of an array being read by [`Decoder::array`].
#[derive(Debug)]
pub struct Elements<'d, 'a> {
    decoder: &'d mut Decoder<'a>,
    remaining: usize,
}

impl<'a> Elements<'_, 'a> {
    /// Elements not read yet.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// The decoder positioned at the next element, which the caller reads exactly once;
    /// `None` after the last one.
    pub fn next_element(&mut self) -> Option<&mut Decoder<'a>> {
        let remaining = self.remaining.checked_sub(1)?;
        self.remaining = remaining;
        Some(self.decoder)
    }
}

/// The entries of a map being read by [`Decoder::map`].
#[derive(Debug)]
pub struct Entries<'d, 'a> {
    decoder: &'d mut Decoder<'a>,
    remaining: usize,
    /// Encoding of the previous key, for the order check.
    previous: Option<&'a [u8]>,
    /// The value of the last key returned has not been read yet.
    value_pending: bool,
}

impl<'a> Entries<'_, 'a> {
    /// The next key in canonical order, or `None` after the last entry. A value the caller did
    /// not read is skipped first.
    ///
    /// # Errors
    ///
    /// [`Error::NotCanonical`] for a key that does not sort after the previous one (§8 order,
    /// which also rules out repeated keys), or the encoding errors of the skipped value or key.
    pub fn next_key(&mut self) -> Result<Option<Key<'a>>, Error> {
        if self.value_pending {
            self.value_pending = false;
            self.decoder.skip()?;
        }
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Ok(None);
        };
        self.remaining = remaining;
        let encoded = self.decoder.encoded_item()?;
        // Keys are compared by encoding, not decoded value: §8 makes the width of a float part
        // of its value, so 1.0 as 16 and as 32 bits are distinct keys; a duplicate is a
        // byte-identical key.
        if let Some(previous) = self.previous
            && canonical_order(previous, encoded) != Ordering::Less
        {
            return Err(Error::NotCanonical);
        }
        self.previous = Some(encoded);
        self.value_pending = true;
        Ok(Some(key(encoded)))
    }

    /// The decoder positioned at the value of the last key, which the caller reads exactly
    /// once.
    pub fn value(&mut self) -> &mut Decoder<'a> {
        debug_assert!(self.value_pending, "value follows next_key");
        self.value_pending = false;
        self.decoder
    }
}

/// §8 key order: lower major type first, then the shorter encoding, then bytewise.
fn canonical_order(left: &[u8], right: &[u8]) -> Ordering {
    let major = |encoded: &[u8]| encoded.first().map(|byte| Major::from_initial(*byte));
    major(left)
        .cmp(&major(right))
        .then(left.len().cmp(&right.len()))
        .then(left.cmp(right))
}

/// Interprets the encoding of a key already checked by [`Decoder::encoded_item`].
fn key(encoded: &[u8]) -> Key<'_> {
    let mut decoder = Decoder::new(encoded);
    match encoded.first().map(|byte| Major::from_initial(*byte)) {
        Some(Major::Unsigned | Major::Negative) => decoder.int().map_or(Key::Other, Key::Int),
        Some(Major::Text) => decoder.text().map_or(Key::Other, Key::Text),
        _ => Key::Other,
    }
}

/// The output buffer of an [`Encoder`] is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

impl fmt::Display for Full {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CBOR output buffer full")
    }
}

impl core::error::Error for Full {}

/// Writes CTAP2 canonical CBOR into a caller-provided buffer. Map keys are written in
/// canonical order by the caller (§8); every response is checked against [`Decoder`] in the
/// tests.
#[derive(Debug)]
pub struct Encoder<'b> {
    output: &'b mut [u8],
    written: usize,
}

impl<'b> Encoder<'b> {
    /// Writes into `output` from its start.
    pub const fn new(output: &'b mut [u8]) -> Self {
        Self { output, written: 0 }
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.output[..self.written]
    }

    /// Number of bytes written so far.
    pub const fn len(&self) -> usize {
        self.written
    }

    /// Whether nothing was written yet.
    pub const fn is_empty(&self) -> bool {
        self.written == 0
    }

    fn put(&mut self, bytes: &[u8]) -> Result<&mut Self, Full> {
        let end = self.written.checked_add(bytes.len()).ok_or(Full)?;
        let target = self.output.get_mut(self.written..end).ok_or(Full)?;
        target.copy_from_slice(bytes);
        self.written = end;
        Ok(self)
    }

    /// An initial byte with the shortest argument for `value` (§8).
    fn head(&mut self, major: Major, value: u64) -> Result<&mut Self, Full> {
        let major = (major as u8) << 5;
        // Each arm holds the value range of its width, so the narrowing casts are exact.
        match value {
            0..=23 => self.put(&[major | value as u8]),
            24..=0xFF => self.put(&[major | ONE_BYTE, value as u8]),
            0x100..=0xFFFF => {
                self.put(&[major | TWO_BYTES])?;
                self.put(&(value as u16).to_be_bytes())
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.put(&[major | FOUR_BYTES])?;
                self.put(&(value as u32).to_be_bytes())
            }
            _ => {
                self.put(&[major | EIGHT_BYTES])?;
                self.put(&value.to_be_bytes())
            }
        }
    }

    /// Writes an unsigned integer.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn unsigned(&mut self, value: u64) -> Result<&mut Self, Full> {
        self.head(Major::Unsigned, value)
    }

    /// Writes an integer of either sign.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn int(&mut self, value: i64) -> Result<&mut Self, Full> {
        match u64::try_from(value) {
            Ok(unsigned) => self.head(Major::Unsigned, unsigned),
            Err(_) => {
                let argument = (-1i64)
                    .checked_sub(value)
                    .and_then(|n| u64::try_from(n).ok())
                    .expect("-1 - value is in 0..=i64::MAX for a negative value");
                self.head(Major::Negative, argument)
            }
        }
    }

    /// Writes a byte string.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn bytes(&mut self, value: &[u8]) -> Result<&mut Self, Full> {
        self.head(Major::Bytes, value.len() as u64)?.put(value)
    }

    /// Writes a text string.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn text(&mut self, value: &str) -> Result<&mut Self, Full> {
        self.head(Major::Text, value.len() as u64)?
            .put(value.as_bytes())
    }

    /// Writes `true` or `false`.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn bool(&mut self, value: bool) -> Result<&mut Self, Full> {
        self.head(Major::Simple, if value { TRUE } else { FALSE })
    }

    /// Writes `null`.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn null(&mut self) -> Result<&mut Self, Full> {
        self.head(Major::Simple, NULL)
    }

    /// Starts an array of `count` elements, written next.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn array(&mut self, count: usize) -> Result<&mut Self, Full> {
        self.head(Major::Array, count as u64)
    }

    /// Starts a map of `count` entries, written next as key, value pairs in canonical key
    /// order.
    ///
    /// # Errors
    ///
    /// [`Full`] when the buffer has no room.
    pub fn map(&mut self, count: usize) -> Result<&mut Self, Full> {
        self.head(Major::Map, count as u64)
    }
}

/// Checks that `input` is exactly one CTAP2 canonical CBOR message.
///
/// # Errors
///
/// The first rule the message breaks.
pub fn validate(input: &[u8]) -> Result<(), Error> {
    let mut decoder = Decoder::new(input);
    decoder.skip()?;
    decoder.finish()
}

#[cfg(test)]
mod tests;

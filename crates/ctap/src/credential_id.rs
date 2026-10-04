//! Credential IDs: everything an assertion needs, sealed with AES-256-GCM under `K_wrap` and
//! bound to the RP ID.
//!
//! ```text
//! credential_id = version (1, 0x01) || nonce (12) || ciphertext || tag (16)
//! AAD           = version || SHA-256(rpId)
//! plaintext     = canonical CBOR map, keys 1..=11 as listed on [`Credential`]
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Decoder, Encoder, Entries, Key};
use crate::crypto::{Crypto, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::keys::KeyRing;

/// The format version this module writes and opens.
pub const VERSION: u8 = 0x01;
/// Longest user ID: WebAuthn L3 §5.1.3 step 5 refuses a `user.id` outside 1..=64 bytes.
pub const MAX_USER_ID_LEN: usize = 64;
/// Longest stored user name and display name, in bytes. WebAuthn L3 §5.4.1 and §5.4.3 let a
/// stored `name` / `displayName` be truncated (§6.4.1.2: on a code point boundary) to any limit
/// of at least 64 bytes; the names travel inside every credential ID the RP stores and sends
/// back, so the smallest permitted limit keeps IDs short.
pub const MAX_NAME_LEN: usize = 64;
/// Credential random seed length.
pub const SEED_LEN: usize = 32;
/// Device-only slot tag length.
pub const SLOT_TAG_LEN: usize = 16;

/// Largest plaintext: the map header and every field at its maximum size.
const MAX_PLAINTEXT_LEN: usize = 1 // map of up to 11 entries
    + 2 // 1: origin
    + 2 + 9 // 2: alg, any i64
    + 1 + 2 + SEED_LEN // 3: cs
    + 1 + 3 // 4: slot, up to u16
    + 1 + 1 + SLOT_TAG_LEN // 5: slot_tag
    + 2 // 6: cred_protect
    + 2 // 7: rk
    + 1 + 2 + MAX_USER_ID_LEN // 8: user_id
    + 2 * (1 + 2 + MAX_NAME_LEN) // 9, 10: names
    + 2 + 5; // 11: epoch, up to u32

/// Longest credential ID, reported as `maxCredentialIdLength`.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1 + NONCE_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;

/// Where the private key of a credential comes from. Its `Debug` output never prints the
/// credential seed.
#[derive(Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Derived from the device seed and this credential seed: reproducible from the recovery
    /// phrase.
    Seed([u8; SEED_LEN]),
    /// Derived from the device key `K_dev` and this credential seed: device-only, for a
    /// non-discoverable credential, which takes no slot.
    Device([u8; SEED_LEN]),
    /// Stored in a device-only NVM slot, bound to the slot by its tag: a discoverable credential.
    Slot {
        /// The slot index.
        index: u16,
        /// The tag the slot held when the credential was created.
        tag: [u8; SLOT_TAG_LEN],
    },
}

impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The seed derives the private key; the slot index and tag are not secret.
            KeySource::Seed(_) => f.write_str("Seed(<redacted>)"),
            KeySource::Device(_) => f.write_str("Device(<redacted>)"),
            KeySource::Slot { index, tag } => f
                .debug_struct("Slot")
                .field("index", index)
                .field("tag", tag)
                .finish(),
        }
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        if let KeySource::Seed(cs) | KeySource::Device(cs) = self {
            cs.zeroize();
        }
    }
}

/// credProtect level (CTAP 2.2 §12.1), stored as 1..=3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredProtect {
    /// userVerificationOptional.
    Optional = 1,
    /// userVerificationOptionalWithCredentialIDList.
    OptionalWithCredentialIdList = 2,
    /// userVerificationRequired.
    Required = 3,
}

impl TryFrom<u64> for CredProtect {
    type Error = OpenError;

    fn try_from(value: u64) -> Result<Self, OpenError> {
        match value {
            1 => Ok(CredProtect::Optional),
            2 => Ok(CredProtect::OptionalWithCredentialIdList),
            3 => Ok(CredProtect::Required),
            _ => Err(OpenError::Plaintext),
        }
    }
}

/// The user of a discoverable credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// The user handle, 1..=64 bytes.
    pub id: Vec<u8>,
    /// The user name, at most [`MAX_NAME_LEN`] bytes.
    pub name: Option<String>,
    /// The display name, at most [`MAX_NAME_LEN`] bytes.
    pub display_name: Option<String>,
}

/// Everything a credential ID carries. Plaintext keys: 1 origin (0 device-only, 1
/// seed-recoverable), 2 alg, 3 cs (seed-recoverable, or device-only under `K_dev`), 4 slot, 5
/// slot_tag, 6 cred_protect, 7 rk, 8 user_id, 9 user name, 10 display name, 11 reset ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// Where the private key comes from.
    pub key: KeySource,
    /// COSE algorithm of the key.
    pub alg: i64,
    /// credProtect level.
    pub cred_protect: CredProtect,
    /// The user of a discoverable credential; `None` for a non-discoverable one.
    pub user: Option<User>,
    /// The device's reset ID at creation: 0 before any reset, otherwise the random value the
    /// last reset drew.
    pub reset_id: u32,
}

/// Why a credential ID does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Shorter than the fixed parts or longer than any ID this module writes.
    Length,
    /// A version this module does not write.
    Version,
    /// The tag does not verify: another RP, another device or altered bytes.
    Authentication,
    /// The authenticated plaintext is not a credential of this format.
    Plaintext,
    /// Created under another reset ID than the device's: a reset since revoked it.
    Revoked,
}

/// Why a credential is refused when sealing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// A field longer than its maximum.
    TooLong,
    /// A key source that does not fit the credential: a slot key belongs to a discoverable
    /// credential, which its entry can delete, and a key under `K_dev` to a non-discoverable one.
    KeySource,
}

/// Whether `key` may carry a credential that is discoverable or not, as `discoverable` says.
const fn key_fits(key: &KeySource, discoverable: bool) -> bool {
    match key {
        KeySource::Seed(_) => true,
        KeySource::Device(_) => !discoverable,
        KeySource::Slot { .. } => discoverable,
    }
}

/// The longest prefix of `text` of at most `max` bytes that ends on a character boundary.
pub fn truncate_on_char_boundary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        // `is_char_boundary(0)` holds, so `end` stays above 0 here.
        end = end.checked_sub(1).expect("0 is a character boundary");
    }
    &text[..end]
}

fn aad<C: Crypto>(crypto: &C, rp_id: &str) -> [u8; 1 + KEY_LEN] {
    let mut aad = [0u8; 1 + KEY_LEN];
    aad[0] = VERSION;
    aad[1..].copy_from_slice(&crypto.sha256(&[rp_id.as_bytes()]));
    aad
}

fn encode(credential: &Credential, output: &mut [u8]) -> Result<usize, SealError> {
    let mut encoder = Encoder::new(output);
    let user = credential.user.as_ref();
    let names = user.map_or(0, |user| {
        usize::from(user.name.is_some()) + usize::from(user.display_name.is_some())
    });
    // origin, alg, key fields (1 or 2), cred_protect, rk, user_id, names, reset ID.
    let key_fields = match credential.key {
        KeySource::Seed(_) | KeySource::Device(_) => 1,
        KeySource::Slot { .. } => 2,
    };
    let entries = 5 + key_fields + usize::from(user.is_some()) + names;
    let write = |encoder: &mut Encoder<'_>| -> Result<(), cbor::Full> {
        encoder.map(entries)?;
        match &credential.key {
            KeySource::Seed(cs) => {
                encoder.unsigned(1)?.unsigned(1)?;
                encoder.unsigned(2)?.int(credential.alg)?;
                encoder.unsigned(3)?.bytes(cs)?;
            }
            KeySource::Device(cs) => {
                encoder.unsigned(1)?.unsigned(0)?;
                encoder.unsigned(2)?.int(credential.alg)?;
                encoder.unsigned(3)?.bytes(cs)?;
            }
            KeySource::Slot { index, tag } => {
                encoder.unsigned(1)?.unsigned(0)?;
                encoder.unsigned(2)?.int(credential.alg)?;
                encoder.unsigned(4)?.unsigned(u64::from(*index))?;
                encoder.unsigned(5)?.bytes(tag)?;
            }
        }
        encoder
            .unsigned(6)?
            .unsigned(credential.cred_protect as u64)?;
        encoder.unsigned(7)?.bool(user.is_some())?;
        if let Some(user) = user {
            encoder.unsigned(8)?.bytes(&user.id)?;
            if let Some(name) = &user.name {
                encoder.unsigned(9)?.text(name)?;
            }
            if let Some(display_name) = &user.display_name {
                encoder.unsigned(10)?.text(display_name)?;
            }
        }
        encoder
            .unsigned(11)?
            .unsigned(u64::from(credential.reset_id))?;
        Ok(())
    };
    write(&mut encoder).map_err(|_| SealError::TooLong)?;
    Ok(encoder.len())
}

/// Seals `credential` for `rp_id`. Names longer than [`MAX_NAME_LEN`] are cut on a character
/// boundary.
///
/// # Errors
///
/// [`SealError::TooLong`] for a user ID outside 1..=64 bytes, [`SealError::KeySource`] for a
/// key source that does not fit the credential's discoverability.
pub fn seal<C: Crypto>(
    crypto: &mut C,
    keys: &KeyRing,
    rp_id: &str,
    credential: &Credential,
) -> Result<Vec<u8>, SealError> {
    if !key_fits(&credential.key, credential.user.is_some()) {
        return Err(SealError::KeySource);
    }
    let mut credential = credential.clone();
    if let Some(user) = &mut credential.user {
        // WebAuthn L3 §5.1.3 step 5: a user ID is 1..=64 bytes.
        if user.id.is_empty() || user.id.len() > MAX_USER_ID_LEN {
            return Err(SealError::TooLong);
        }
        for name in [&mut user.name, &mut user.display_name]
            .into_iter()
            .flatten()
        {
            let kept = truncate_on_char_boundary(name, MAX_NAME_LEN).len();
            name.truncate(kept);
        }
    }
    let mut plaintext = Zeroizing::new([0u8; MAX_PLAINTEXT_LEN]);
    let length = encode(&credential, &mut plaintext[..])?;
    let mut nonce = [0u8; NONCE_LEN];
    crypto.random(&mut nonce);
    let key = keys.wrap_key(crypto);
    let aad = aad(crypto, rp_id);
    let data = &mut plaintext[..length];
    let tag = crypto.aes256_gcm_seal(&key, &nonce, &aad, data);
    let mut id = Vec::with_capacity(1 + NONCE_LEN + length + TAG_LEN);
    id.push(VERSION);
    id.extend_from_slice(&nonce);
    id.extend_from_slice(data);
    id.extend_from_slice(&tag);
    Ok(id)
}

/// Opens a credential ID presented for `rp_id` on a device whose reset ID is `reset_id`. While it
/// is nonzero, only an ID created under it opens: a reset invalidates every credential (CTAP 2.2
/// §6.6), and a seed-recoverable one would still derive its key from the recovery phrase, so the
/// reset ID is what refuses it. At 0 (never reset, or NVM wiped without a restore) every ID opens,
/// so the credentials the phrase reproduces work again after a reinstall.
///
/// # Errors
///
/// [`OpenError`] when the ID was not sealed by this device for this RP, is not of this format,
/// or was revoked by a reset ([`OpenError::Revoked`]).
pub fn open<C: Crypto>(
    crypto: &C,
    keys: &KeyRing,
    rp_id: &str,
    id: &[u8],
    reset_id: u32,
) -> Result<Credential, OpenError> {
    let credential = open_any_reset(crypto, keys, rp_id, id)?;
    if reset_id != 0 && credential.reset_id != reset_id {
        return Err(OpenError::Revoked);
    }
    Ok(credential)
}

/// Opens a credential ID whatever its reset ID.
fn open_any_reset<C: Crypto>(
    crypto: &C,
    keys: &KeyRing,
    rp_id: &str,
    id: &[u8],
) -> Result<Credential, OpenError> {
    if id.len() < 1 + NONCE_LEN + TAG_LEN || id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(OpenError::Length);
    }
    // Checked splits: the host chose these bytes, so a short ID is refused, never sliced past.
    let (&version, rest) = id.split_first().ok_or(OpenError::Length)?;
    if version != VERSION {
        return Err(OpenError::Version);
    }
    let (nonce, rest) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(OpenError::Length)?;
    let (ciphertext, tag) = rest
        .split_last_chunk::<TAG_LEN>()
        .ok_or(OpenError::Length)?;
    let mut plaintext = Zeroizing::new([0u8; MAX_PLAINTEXT_LEN]);
    let data = &mut plaintext[..ciphertext.len()];
    data.copy_from_slice(ciphertext);
    let key = keys.wrap_key(crypto);
    crypto
        .aes256_gcm_open(&key, nonce, &aad(crypto, rp_id), data, tag)
        .map_err(|_| OpenError::Authentication)?;
    decode(data).map_err(|_| OpenError::Plaintext)
}

/// A plaintext that is canonical CBOR but not a credential of this format.
const NOT_A_CREDENTIAL: cbor::Error = cbor::Error::UnexpectedType;

/// Reads the next key and checks it is `expected`.
fn expect_key(entries: &mut Entries<'_, '_>, expected: i64) -> Result<(), cbor::Error> {
    match entries.next_key()? {
        Some(Key::Int(key)) if key == expected => Ok(()),
        _ => Err(NOT_A_CREDENTIAL),
    }
}

/// Reads the next key, if any, as an integer key.
fn next_int_key(entries: &mut Entries<'_, '_>) -> Result<Option<i64>, cbor::Error> {
    match entries.next_key()? {
        None => Ok(None),
        Some(Key::Int(key)) => Ok(Some(key)),
        Some(_) => Err(NOT_A_CREDENTIAL),
    }
}

fn fixed_bytes<const N: usize>(entries: &mut Entries<'_, '_>) -> Result<[u8; N], cbor::Error> {
    entries
        .value()
        .bytes()?
        .try_into()
        .map_err(|_| NOT_A_CREDENTIAL)
}

/// Reads an optional name at `key`, advancing `next` past it.
fn optional_name(
    entries: &mut Entries<'_, '_>,
    key: i64,
    next: &mut Option<i64>,
) -> Result<Option<String>, cbor::Error> {
    if *next != Some(key) {
        return Ok(None);
    }
    let text = entries.value().text()?;
    if text.len() > MAX_NAME_LEN {
        return Err(NOT_A_CREDENTIAL);
    }
    let text = String::from(text);
    *next = next_int_key(entries)?;
    Ok(Some(text))
}

/// Reads the credential seed of a [`KeySource::Seed`] or [`KeySource::Device`] `key`, copied
/// straight into it: no plain array holds the seed on its way there (the source is the zeroizing
/// plaintext buffer).
fn seed_source(
    entries: &mut Entries<'_, '_>,
    mut key: KeySource,
) -> Result<KeySource, cbor::Error> {
    let source = entries.value().bytes()?;
    if source.len() != SEED_LEN {
        return Err(NOT_A_CREDENTIAL);
    }
    if let KeySource::Seed(seed) | KeySource::Device(seed) = &mut key {
        seed.copy_from_slice(source);
    }
    Ok(key)
}

/// Reads the plaintext map: the keys of its origin, in canonical order, and nothing else.
fn decode(plaintext: &[u8]) -> Result<Credential, cbor::Error> {
    let mut decoder = Decoder::new(plaintext);
    let credential = decoder.map(|entries| {
        expect_key(entries, 1)?;
        let origin = entries.value().unsigned()?;
        expect_key(entries, 2)?;
        let alg = entries.value().int()?;
        let key = match (origin, next_int_key(entries)?) {
            (0, Some(4)) => {
                let index =
                    u16::try_from(entries.value().unsigned()?).map_err(|_| NOT_A_CREDENTIAL)?;
                expect_key(entries, 5)?;
                let tag = fixed_bytes(entries)?;
                KeySource::Slot { index, tag }
            }
            (0, Some(3)) => seed_source(entries, KeySource::Device([0; SEED_LEN]))?,
            (1, Some(3)) => seed_source(entries, KeySource::Seed([0; SEED_LEN]))?,
            _ => return Err(NOT_A_CREDENTIAL),
        };
        expect_key(entries, 6)?;
        let cred_protect =
            CredProtect::try_from(entries.value().unsigned()?).map_err(|_| NOT_A_CREDENTIAL)?;
        expect_key(entries, 7)?;
        let rk = entries.value().bool()?;
        let mut next = next_int_key(entries)?;
        let user = if rk {
            if next != Some(8) {
                return Err(NOT_A_CREDENTIAL);
            }
            let id = entries.value().bytes()?.to_vec();
            // WebAuthn L3 §5.1.3 step 5: a user ID is 1..=64 bytes.
            if id.is_empty() || id.len() > MAX_USER_ID_LEN {
                return Err(NOT_A_CREDENTIAL);
            }
            next = next_int_key(entries)?;
            let name = optional_name(entries, 9, &mut next)?;
            let display_name = optional_name(entries, 10, &mut next)?;
            Some(User {
                id,
                name,
                display_name,
            })
        } else {
            None
        };
        if !key_fits(&key, user.is_some()) {
            return Err(NOT_A_CREDENTIAL);
        }
        if next != Some(11) {
            return Err(NOT_A_CREDENTIAL);
        }
        let reset_id = u32::try_from(entries.value().unsigned()?).map_err(|_| NOT_A_CREDENTIAL)?;
        if entries.next_key()?.is_some() {
            return Err(NOT_A_CREDENTIAL);
        }
        Ok(Credential {
            key,
            alg,
            cred_protect,
            user,
            reset_id,
        })
    })?;
    decoder.finish()?;
    Ok(credential)
}

#[cfg(test)]
mod tests;

//! Persistent state in the application's NVM: the configuration, the discoverable index and the
//! device-only key slots, each a fixed-size record the device updates atomically ([`Storage`]).
//!
//! Two rules keep the records consistent with each other, so a power loss between two writes
//! leaves the state an operation started from or the state it ends in:
//!
//! - Every slot carries the generation of the configuration it was written under. A reset writes
//!   a configuration with the next generation, which empties every slot in that one write; the
//!   slots are wiped afterwards, and [`Store::open`] finishes a wipe that a power loss interrupted.
//! - Every key slot names the index slot and creation sequence of the discoverable credential it
//!   belongs to. The key is written before the entry and counts only while that entry is in the
//!   index, so replacing or removing the entry retires its key in the same write. A
//!   non-discoverable device-only credential takes no slot: its key derives from the device key
//!   kept in the configuration ([`Store::device_key`]).

use alloc::vec::Vec;
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::credential_id::{KeySource, MAX_CREDENTIAL_ID_LEN, SLOT_TAG_LEN, StoreId};
use crate::crypto::{Crypto, KEY_LEN};
use crate::ctap2::StatusCode;

#[cfg(feature = "soft")]
mod memory;
#[cfg(feature = "soft")]
pub use memory::MemoryStorage;

/// Version of the record layout below, stored in the configuration. NVM that holds another
/// version (or none: a fresh install reads all zeros) is wiped and formatted on open.
pub const LAYOUT_VERSION: u8 = 2;
/// Longest RP ID kept in an index entry, in bytes.
pub const MAX_RP_ID_LEN: usize = 64;
/// Length of the stored PIN verifier, `LEFT(SHA-256(PIN), 16)` (CTAP 2.2 §6.5.5.5).
pub const PIN_VERIFIER_LEN: usize = 16;
/// PIN retries after a reset: CTAP 2.2 §6.5.2.3 allows at most 8. The maximum is kept, since a
/// guesser is already held to 8 attempts in all and to a power cycle after every three
/// consecutive mismatches (§6.5.5.7.2), and a lower count only blocks the PIN of a user who
/// mistyped.
pub const PIN_RETRIES: u8 = 8;

/// Marks a slot record in use; a free slot is all zeros.
const USED: u8 = 1;

// Configuration record: version, generation, reset ID, alwaysUv, PIN retries, PIN set, verifier,
// creation sequence limit, device key set, device key, store ID (0: none yet).
const CONFIG_VERSION: usize = 0;
const CONFIG_GENERATION: usize = 1;
const CONFIG_RESET_ID: usize = 5;
const CONFIG_ALWAYS_UV: usize = 9;
const CONFIG_PIN_RETRIES: usize = 10;
const CONFIG_PIN_SET: usize = 11;
const CONFIG_PIN: usize = 12;
const CONFIG_SEQUENCE_LIMIT: usize = CONFIG_PIN + PIN_VERIFIER_LEN;
const CONFIG_DEVICE_KEY_SET: usize = CONFIG_SEQUENCE_LIMIT + 4;
const CONFIG_DEVICE_KEY: usize = CONFIG_DEVICE_KEY_SET + 1;
const CONFIG_STORE_ID: usize = CONFIG_DEVICE_KEY + KEY_LEN;
/// Length of the configuration record.
pub const CONFIG_LEN: usize = CONFIG_STORE_ID + 4;

/// Creation sequences are handed out in blocks: the configuration records the end of the
/// current block, so one configuration write covers this many creations and a sequence below
/// the recorded limit is never handed out again, also after a reopen or a reset.
const SEQUENCE_BLOCK: u32 = 32;

/// Marks where a stored RP ID was cut (CTAP 2.2 §6.8.7: U+2026, horizontal ellipsis).
const ELLIPSIS: &str = "…";

// Index entry: state, generation, creation sequence, RP ID hash, RP ID, credential ID.
const ENTRY_STATE: usize = 0;
const ENTRY_GENERATION: usize = 1;
const ENTRY_SEQUENCE: usize = 5;
const ENTRY_RP_ID_HASH: usize = 9;
const ENTRY_RP_ID_LEN: usize = ENTRY_RP_ID_HASH + KEY_LEN;
const ENTRY_RP_ID: usize = ENTRY_RP_ID_LEN + 1;
const ENTRY_CREDENTIAL_ID_LEN: usize = ENTRY_RP_ID + MAX_RP_ID_LEN;
const ENTRY_CREDENTIAL_ID: usize = ENTRY_CREDENTIAL_ID_LEN + 2;
/// Length of an index entry record.
pub const INDEX_ENTRY_LEN: usize = ENTRY_CREDENTIAL_ID + MAX_CREDENTIAL_ID_LEN;

// Key slot: state, generation, owner (index slot, sequence), tag, key, two CredRandom.
const KEY_STATE: usize = 0;
const KEY_GENERATION: usize = 1;
const KEY_OWNER_SLOT: usize = 5;
const KEY_OWNER_SEQUENCE: usize = 7;
const KEY_TAG: usize = 11;
const KEY_PRIVATE: usize = KEY_TAG + SLOT_TAG_LEN;
const KEY_CRED_RANDOM_UV: usize = KEY_PRIVATE + KEY_LEN;
const KEY_CRED_RANDOM: usize = KEY_CRED_RANDOM_UV + KEY_LEN;
/// Length of a device-only key slot record.
pub const KEY_SLOT_LEN: usize = KEY_CRED_RANDOM + KEY_LEN;

/// The NVM regions of the device. Each write replaces one record atomically: after a power loss
/// the record holds the value before the write or the value written, never a mix. The device
/// implements it with the SDK's atomic storage; [`MemoryStorage`] is the host double.
///
/// A record never written reads as all zeros. Slot numbers passed in are below the slot count.
/// A write leaves no earlier value of the record anywhere in NVM: key slots hold private keys
/// and the configuration holds the PIN verifier, so a wiped record must be gone, not shadowed.
pub trait Storage {
    /// The configuration record.
    fn config(&self) -> &[u8; CONFIG_LEN];
    /// Replaces the configuration record.
    fn write_config(&mut self, record: &[u8; CONFIG_LEN]);
    /// Number of discoverable index slots.
    fn index_slots(&self) -> usize;
    /// The index entry record of `slot`.
    fn index_entry(&self, slot: usize) -> &[u8; INDEX_ENTRY_LEN];
    /// Replaces the index entry record of `slot`.
    fn write_index_entry(&mut self, slot: usize, record: &[u8; INDEX_ENTRY_LEN]);
    /// Number of device-only key slots.
    fn key_slots(&self) -> usize;
    /// The key slot record of `slot`.
    fn key_slot(&self, slot: usize) -> &[u8; KEY_SLOT_LEN];
    /// Replaces the key slot record of `slot`.
    fn write_key_slot(&mut self, slot: usize, record: &[u8; KEY_SLOT_LEN]);
}

/// Why a store operation was refused. Nothing was written when it is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No free slot: CTAP2_ERR_KEY_STORE_FULL.
    Full,
    /// An RP ID or credential ID longer than its record field.
    TooLong,
    /// A creation sequence, generation or epoch counter would wrap.
    Exhausted,
    /// The reservation was made before a reset.
    Stale,
}

impl From<StoreError> for StatusCode {
    /// CTAP 2.2 §6.1.2 step 17.4: no room for a discoverable credential is
    /// CTAP2_ERR_KEY_STORE_FULL; the other refusals are internal and stay CTAP1_ERR_OTHER.
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Full => StatusCode::KeyStoreFull,
            StoreError::TooLong | StoreError::Exhausted | StoreError::Stale => StatusCode::Other,
        }
    }
}

/// The stored client PIN verifier, `LEFT(SHA-256(PIN), 16)`. Zeroized on drop; its `Debug`
/// output never prints it.
#[derive(Clone)]
pub struct PinVerifier([u8; PIN_VERIFIER_LEN]);

impl PinVerifier {
    /// Wraps a verifier computed by the PIN protocol.
    pub const fn new(verifier: [u8; PIN_VERIFIER_LEN]) -> Self {
        Self(verifier)
    }

    /// Whether `candidate` equals this verifier, in time independent of both.
    pub fn matches(&self, candidate: &[u8; PIN_VERIFIER_LEN]) -> bool {
        constant_time_eq(&self.0, candidate)
    }
}

impl Drop for PinVerifier {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinVerifier(<redacted>)")
    }
}

/// The configuration region.
#[derive(Clone, Debug)]
pub struct Config {
    /// Reset ID: 0 before any reset, a fresh random nonzero value after each, written into new
    /// credential IDs. Only a reset changes it; [`Store::write_config`] keeps the stored one.
    pub reset_id: u32,
    /// `alwaysUv` (CTAP 2.2 §7.2).
    pub always_uv: bool,
    /// The client PIN, if one is set.
    pub pin: Option<PinVerifier>,
    /// Remaining PIN attempts.
    pub pin_retries: u8,
}

impl Config {
    /// The configuration after a reset to `reset_id`: no PIN, full retries, `alwaysUv` off.
    pub const fn after_reset(reset_id: u32) -> Self {
        Self {
            reset_id,
            always_uv: false,
            pin: None,
            pin_retries: PIN_RETRIES,
        }
    }
}

/// An entry of the discoverable index, borrowed from NVM.
#[derive(Clone, Copy, Debug)]
pub struct IndexEntry<'a> {
    /// Which slot and creation it is.
    pub id: EntryId,
    /// SHA-256 of the RP ID.
    pub rp_id_hash: &'a [u8; KEY_LEN],
    /// The RP ID, kept so credential management can list relying parties without a key; at
    /// most [`MAX_RP_ID_LEN`] bytes, a longer one in the truncated form of CTAP 2.2 §6.8.7. Only
    /// shown, never compared: lookups use `rp_id_hash`.
    pub rp_id: &'a str,
    /// The full credential ID.
    pub credential_id: &'a [u8],
}

/// One creation of an index entry: its slot and creation sequence. A later credential in the
/// same slot has another sequence, so an `EntryId` never names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryId {
    /// The index slot.
    pub slot: u16,
    /// The creation sequence: larger is newer.
    pub sequence: u32,
}

/// The secrets of a device-only credential.
pub struct DeviceKey {
    /// The P-256 private key.
    pub private_key: Zeroizing<[u8; KEY_LEN]>,
    /// CredRandom for ceremonies with user verification.
    pub cred_random_uv: Zeroizing<[u8; KEY_LEN]>,
    /// CredRandom for ceremonies without user verification.
    pub cred_random: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

/// An index slot chosen for a new discoverable credential, from [`Store::reserve`] to
/// [`Store::commit`] or [`Store::release`].
#[must_use = "a reservation is committed or released"]
#[derive(Debug)]
pub struct Reservation {
    id: EntryId,
    generation: u32,
    rp_id_hash: [u8; KEY_LEN],
    rp_id: [u8; MAX_RP_ID_LEN],
    rp_id_len: u8,
    /// The entry this one replaces owns a device-only key, which its commit frees.
    replaces_key: bool,
}

impl Reservation {
    /// The slot and creation sequence the entry will have.
    pub const fn id(&self) -> EntryId {
        self.id
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0 && left.len() == right.len()
}

fn read_u16(record: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([record[at], record[at + 1]])
}

fn read_u32(record: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
}

fn write_u16(record: &mut [u8], at: usize, value: u16) {
    record[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(record: &mut [u8], at: usize, value: u32) {
    record[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn is_zero(record: &[u8]) -> bool {
    record.iter().all(|&byte| byte == 0)
}

/// The stored form of `rp_id` and its length: CTAP 2.2 §6.8.7's truncation procedure with
/// [`MAX_RP_ID_LEN`] for its 32-byte length (the protocol up to the first colon, U+2026, then the
/// end of the RP ID). Where its byte offsets fall inside a UTF-8 character, the protocol stops and
/// the end starts at the neighbouring boundary, so the stored RP ID stays text: credential
/// management returns it as a CBOR text string, which must be UTF-8 (RFC 8949 §3.1, major type 3).
/// Web RP IDs are ASCII domains, where this is the procedure exactly.
pub(crate) fn stored_rp_id(rp_id: &str) -> ([u8; MAX_RP_ID_LEN], usize) {
    let mut stored = [0u8; MAX_RP_ID_LEN];
    let bytes = rp_id.as_bytes();
    if bytes.len() <= MAX_RP_ID_LEN {
        stored[..bytes.len()].copy_from_slice(bytes);
        return (stored, bytes.len());
    }
    let mut used = 0;
    if let Some(colon) = rp_id.find(':') {
        used = rp_id.floor_char_boundary((colon + 1).min(MAX_RP_ID_LEN));
        stored[..used].copy_from_slice(&bytes[..used]);
    }
    // `used` is at most MAX_RP_ID_LEN.
    if MAX_RP_ID_LEN - used < ELLIPSIS.len() {
        return (stored, used);
    }
    stored[used..used + ELLIPSIS.len()].copy_from_slice(ELLIPSIS.as_bytes());
    used += ELLIPSIS.len();
    // The RP ID is longer than MAX_RP_ID_LEN, so the start is past 0.
    let start = rp_id.ceil_char_boundary(bytes.len() - (MAX_RP_ID_LEN - used));
    let end = &bytes[start..];
    stored[used..used + end.len()].copy_from_slice(end);
    (stored, used + end.len())
}

/// Slot numbers are 16-bit in records and credential IDs; a region with more slots uses the
/// first 65535.
fn slot_count(slots: usize) -> u16 {
    u16::try_from(slots).unwrap_or(u16::MAX)
}

/// The persistent state on top of a [`Storage`]. One reservation is outstanding at a time:
/// commands are processed one after another.
#[derive(Debug)]
pub struct Store<S> {
    storage: S,
    generation: u32,
    /// The creation sequence of the next reservation; above `u32::MAX` when exhausted.
    next_sequence: u64,
    /// The end of the block of creation sequences recorded in the configuration.
    sequence_limit: u32,
}

impl<S: Storage> Store<S> {
    /// Opens the state: formats NVM of another layout, wipes what a reset or a replaced entry
    /// left behind (also when a power loss interrupted that), and finds the next creation
    /// sequence.
    pub fn open(mut storage: S) -> Self {
        // Read in place: the record holds the PIN verifier.
        if storage.config()[CONFIG_VERSION] != LAYOUT_VERSION {
            // Slots first: until the configuration is written, an interrupted format restarts.
            for slot in 0..storage.index_slots() {
                if !is_zero(storage.index_entry(slot)) {
                    storage.write_index_entry(slot, &[0; INDEX_ENTRY_LEN]);
                }
            }
            for slot in 0..storage.key_slots() {
                if !is_zero(storage.key_slot(slot)) {
                    storage.write_key_slot(slot, &[0; KEY_SLOT_LEN]);
                }
            }
            let mut store = Self {
                storage,
                generation: 0,
                next_sequence: 0,
                sequence_limit: 0,
            };
            // Reset ID 0 by design, not a lost revocation. Ledger OS replaces an application's
            // NVM when it installs or updates the application, so a format only ever meets a
            // fresh region and no state of the previous install survives anywhere the
            // application can write. A seed-recoverable credential is reproducible from the
            // recovery phrase by definition (it reports backup eligible and backed up, BE=BS=1):
            // the phrase is its backup, as a synced provider's account is for a synced passkey,
            // and restoring the phrase onto fresh NVM brings it back. Reset therefore revokes such
            // credentials for as long as this NVM lives; the reset ID travels in the encrypted
            // backup, and the reset confirmation screen says both. Device-only credentials are
            // unaffected: their keys are gone with the NVM.
            // No device key and no store ID: the record of another layout holds none that this
            // one could read, and the first discoverable credential draws the store ID.
            store.write_record(&Config::after_reset(0), 0, None, 0);
            return store;
        }
        let mut store = Self {
            generation: read_u32(storage.config(), CONFIG_GENERATION),
            sequence_limit: read_u32(storage.config(), CONFIG_SEQUENCE_LIMIT),
            storage,
            next_sequence: 0,
        };
        store.sweep();
        store
    }

    /// The storage underneath.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// The configuration.
    pub fn config(&self) -> Config {
        let record = self.storage.config();
        // Copied straight into the zeroizing verifier: no plain array holds it on the way.
        let pin = (record[CONFIG_PIN_SET] == USED).then(|| {
            let mut pin = PinVerifier::new([0; PIN_VERIFIER_LEN]);
            pin.0
                .copy_from_slice(&record[CONFIG_PIN..CONFIG_PIN + PIN_VERIFIER_LEN]);
            pin
        });
        Config {
            reset_id: read_u32(record, CONFIG_RESET_ID),
            always_uv: record[CONFIG_ALWAYS_UV] == USED,
            pin,
            pin_retries: record[CONFIG_PIN_RETRIES],
        }
    }

    /// Replaces the configuration in one write; the device key and the stored reset ID stay,
    /// whatever `config` carries. Only a reset changes the reset ID: a write from a stale
    /// `Config` must not bring back one a reset replaced, which would open the credential IDs it
    /// revoked.
    pub fn write_config(&mut self, config: &Config) {
        let device_key = self.device_key();
        let reset_id = read_u32(self.storage.config(), CONFIG_RESET_ID);
        let store_id = read_u32(self.storage.config(), CONFIG_STORE_ID);
        self.write_record(config, reset_id, device_key.as_deref(), store_id);
    }

    /// The store ID of this NVM, if a discoverable credential was created since it was
    /// formatted.
    pub fn store_id(&self) -> Option<StoreId> {
        StoreId::new(read_u32(self.storage.config(), CONFIG_STORE_ID))
    }

    /// The store ID of this NVM, first drawn from the TRNG and written into the configuration if
    /// there is none: a random nonzero value, kept until NVM is formatted again (a reset keeps
    /// it, as the reset ID already revokes what was created before).
    pub fn store_id_or_create<C: Crypto>(&mut self, crypto: &mut C) -> StoreId {
        if let Some(store_id) = self.store_id() {
            return store_id;
        }
        // Drawn until nonzero: a draw is 0 with probability 2^-32.
        let store_id = loop {
            let mut bytes = [0u8; 4];
            crypto.random(&mut bytes);
            if let Some(store_id) = StoreId::new(u32::from_le_bytes(bytes)) {
                break store_id;
            }
        };
        let config = self.config();
        let device_key = self.device_key();
        self.write_record(
            &config,
            config.reset_id,
            device_key.as_deref(),
            store_id.get(),
        );
        store_id
    }

    /// The device key `K_dev` of non-discoverable device-only credentials, if one was created
    /// since the last reset; without it no such credential opens.
    pub fn device_key(&self) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let record = self.storage.config();
        (record[CONFIG_DEVICE_KEY_SET] == USED).then(|| {
            // Copied straight into the zeroizing buffer: no plain array holds it on the way.
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&record[CONFIG_DEVICE_KEY..CONFIG_STORE_ID]);
            key
        })
    }

    /// The device key, first drawn from the TRNG and written into the configuration if there is
    /// none since the last reset.
    pub fn device_key_or_create<C: Crypto>(&mut self, crypto: &mut C) -> Zeroizing<[u8; KEY_LEN]> {
        if let Some(key) = self.device_key() {
            return key;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        crypto.random(&mut key[..]);
        let config = self.config();
        let store_id = read_u32(self.storage.config(), CONFIG_STORE_ID);
        self.write_record(&config, config.reset_id, Some(&key), store_id);
        key
    }

    /// Writes `config` with `reset_id` in place of its own, so a caller can keep the stored reset
    /// ID without copying the rest of the configuration (it holds the PIN verifier), and with
    /// `store_id` (0 for none).
    fn write_record(
        &mut self,
        config: &Config,
        reset_id: u32,
        device_key: Option<&[u8; KEY_LEN]>,
        store_id: u32,
    ) {
        let mut record = Zeroizing::new([0u8; CONFIG_LEN]);
        record[CONFIG_VERSION] = LAYOUT_VERSION;
        write_u32(&mut record[..], CONFIG_GENERATION, self.generation);
        write_u32(&mut record[..], CONFIG_RESET_ID, reset_id);
        record[CONFIG_ALWAYS_UV] = u8::from(config.always_uv);
        record[CONFIG_PIN_RETRIES] = config.pin_retries;
        if let Some(pin) = &config.pin {
            record[CONFIG_PIN_SET] = USED;
            record[CONFIG_PIN..CONFIG_SEQUENCE_LIMIT].copy_from_slice(&pin.0);
        }
        write_u32(&mut record[..], CONFIG_SEQUENCE_LIMIT, self.sequence_limit);
        if let Some(key) = device_key {
            record[CONFIG_DEVICE_KEY_SET] = USED;
            record[CONFIG_DEVICE_KEY..CONFIG_STORE_ID].copy_from_slice(key);
        }
        write_u32(&mut record[..], CONFIG_STORE_ID, store_id);
        self.storage.write_config(&record);
    }

    /// authenticatorReset (CTAP 2.2 §6.6): empties the index and the key slots and writes the
    /// configuration after a reset with a new reset ID and no device key, all in one write, then
    /// wipes the slots. §6.6 requires every credential to stop working and the PIN, `alwaysUv`
    /// and the discoverable state to be cleared: device-only keys, the device key and entries are
    /// erased, and seed-recoverable credential IDs of any other reset ID are refused when opened.
    /// The new reset ID is random, nonzero and not the current one, so it differs from every ID
    /// created since the last reset, also after an NVM wipe that lost the earlier ones.
    ///
    /// # Errors
    ///
    /// [`StoreError::Exhausted`] when the generation would wrap.
    pub fn reset<C: Crypto>(&mut self, crypto: &mut C) -> Result<(), StoreError> {
        let current = self.config().reset_id;
        // 32 bits from the TRNG: the draw matches one of n earlier reset IDs with probability
        // n / 2^32, and n counts resets a person confirmed on the device within 10 seconds of
        // opening the application, so it stays in the tens. Nobody can steer the draw, and a
        // wider ID would lengthen every credential ID for a risk of the order of 10^-8.
        let reset_id = loop {
            let mut bytes = [0u8; 4];
            crypto.random(&mut bytes);
            let drawn = u32::from_le_bytes(bytes);
            if drawn != 0 && drawn != current {
                break drawn;
            }
        };
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(StoreError::Exhausted)?;
        // The store ID stays: the new reset ID already refuses every ID created before.
        let store_id = read_u32(self.storage.config(), CONFIG_STORE_ID);
        self.write_record(&Config::after_reset(reset_id), reset_id, None, store_id);
        self.sweep();
        Ok(())
    }

    /// `remainingDiscoverableCredentials`: discoverable credentials that fit whatever their key
    /// origin, so free index slots bounded by the key slots a device-only one would need. CTAP 2.2
    /// §6.4 (member 0x14) wants zero whenever a creation may fail for lack of space, even if
    /// a particular request would succeed.
    pub fn remaining_discoverable(&self) -> usize {
        let free_entries = (0..slot_count(self.storage.index_slots()))
            .filter(|&slot| self.entry(slot).is_none())
            .count();
        free_entries.min(self.remaining_keys())
    }

    /// Device-only key slots free for new credentials. One free slot is always kept back for
    /// replacing a device-only credential, whose old key holds its slot until the new entry is
    /// written; it is not counted.
    pub fn remaining_keys(&self) -> usize {
        // Clamped at 0 by design: with no free slot or only the spare, nothing is available.
        self.free_keys().saturating_sub(1)
    }

    fn free_keys(&self) -> usize {
        (0..slot_count(self.storage.key_slots()))
            .filter(|&slot| self.key_is_free(slot))
            .count()
    }

    /// The entry in `slot`, if the slot holds one.
    pub fn entry(&self, slot: u16) -> Option<IndexEntry<'_>> {
        if slot >= slot_count(self.storage.index_slots()) {
            return None;
        }
        let record = self.storage.index_entry(usize::from(slot));
        if record[ENTRY_STATE] != USED || read_u32(record, ENTRY_GENERATION) != self.generation {
            return None;
        }
        let rp_id_len = usize::from(record[ENTRY_RP_ID_LEN]);
        let credential_id_len = usize::from(read_u16(record, ENTRY_CREDENTIAL_ID_LEN));
        // The device wrote these within bounds; a record that is not is treated as free and
        // wiped on the next open.
        if rp_id_len > MAX_RP_ID_LEN || credential_id_len > MAX_CREDENTIAL_ID_LEN {
            return None;
        }
        let rp_id = core::str::from_utf8(&record[ENTRY_RP_ID..ENTRY_RP_ID + rp_id_len]).ok()?;
        let rp_id_hash = record[ENTRY_RP_ID_HASH..ENTRY_RP_ID_HASH + KEY_LEN]
            .try_into()
            .ok()?;
        Some(IndexEntry {
            id: EntryId {
                slot,
                sequence: read_u32(record, ENTRY_SEQUENCE),
            },
            rp_id_hash,
            rp_id,
            credential_id: &record[ENTRY_CREDENTIAL_ID..ENTRY_CREDENTIAL_ID + credential_id_len],
        })
    }

    /// Every entry of the index, in slot order.
    pub fn entries(&self) -> impl Iterator<Item = IndexEntry<'_>> {
        (0..slot_count(self.storage.index_slots())).filter_map(|slot| self.entry(slot))
    }

    /// The entries for `rp_id_hash`, most recently created first, the order CTAP 2.2 §6.2.2 step
    /// 12.2.1 sets for a request without an allowList.
    pub fn newest_first(&self, rp_id_hash: &[u8; KEY_LEN]) -> Vec<IndexEntry<'_>> {
        let mut entries: Vec<_> = self
            .entries()
            .filter(|entry| entry.rp_id_hash == rp_id_hash)
            .collect();
        entries.sort_unstable_by_key(|entry| core::cmp::Reverse(entry.id.sequence));
        entries
    }

    /// Chooses the slot of a new discoverable credential: the slot of the credential that
    /// `same_user` recognises for this RP, which the new one replaces (CTAP 2.2 §6.1.2 step
    /// 17.2), or else a free slot. `same_user` opens a stored credential ID and compares its user
    /// ID. An RP ID over [`MAX_RP_ID_LEN`] bytes is kept in the truncated form of CTAP 2.2
    /// §6.8.7; `rp_id_hash` stays the full RP ID's.
    ///
    /// # Errors
    ///
    /// [`StoreError::Full`] without a slot, [`StoreError::Exhausted`] when creation sequences
    /// ran out.
    pub fn reserve(
        &mut self,
        rp_id_hash: &[u8; KEY_LEN],
        rp_id: &str,
        mut same_user: impl FnMut(&IndexEntry<'_>) -> bool,
    ) -> Result<Reservation, StoreError> {
        let (stored_rp_id, stored_len) = stored_rp_id(rp_id);
        // At most MAX_RP_ID_LEN = 64.
        let rp_id_len = u8::try_from(stored_len).map_err(|_| StoreError::TooLong)?;
        let sequence = u32::try_from(self.next_sequence).map_err(|_| StoreError::Exhausted)?;
        let mut free = None;
        let mut replaced = None;
        for slot in 0..slot_count(self.storage.index_slots()) {
            match self.entry(slot) {
                Some(entry) => {
                    if entry.rp_id_hash == rp_id_hash && same_user(&entry) {
                        replaced = Some(slot);
                        break;
                    }
                }
                None => {
                    free.get_or_insert(slot);
                }
            }
        }
        let slot = replaced.or(free).ok_or(StoreError::Full)?;
        let replaces_key = replaced
            .and_then(|slot| self.entry(slot))
            .is_some_and(|entry| self.owns_key(entry.id));
        if sequence >= self.sequence_limit {
            // Record the next block before handing out its first sequence. Capped at u32::MAX,
            // past which sequences are exhausted.
            let limit = sequence.saturating_add(SEQUENCE_BLOCK);
            if sequence >= limit {
                return Err(StoreError::Exhausted);
            }
            self.sequence_limit = limit;
            self.write_config(&self.config());
        }
        self.next_sequence = u64::from(sequence) + 1;
        Ok(Reservation {
            id: EntryId { slot, sequence },
            generation: self.generation,
            rp_id_hash: *rp_id_hash,
            rp_id: stored_rp_id,
            rp_id_len,
            replaces_key,
        })
    }

    /// Stores the secrets of a new discoverable device-only credential in a free key slot under a
    /// fresh tag. The key belongs to `owner` and counts only once that reservation is committed.
    /// A non-discoverable device-only credential takes no slot: its key derives from
    /// [`Store::device_key_or_create`].
    ///
    /// The last free slot is kept for replacing a device-only credential (CTAP 2.2 §6.1.2 step
    /// 17.2): the old key holds its slot until the new entry is written, so such a replacement
    /// may take it, and every other key needs a second free slot.
    ///
    /// # Errors
    ///
    /// [`StoreError::Full`] without a free key slot, [`StoreError::Stale`] for a reservation
    /// made before a reset.
    pub fn store_key<C: Crypto>(
        &mut self,
        crypto: &mut C,
        owner: &Reservation,
        key: &DeviceKey,
    ) -> Result<KeySource, StoreError> {
        if owner.generation != self.generation {
            return Err(StoreError::Stale);
        }
        let needed = if owner.replaces_key { 1 } else { 2 };
        if self.free_keys() < needed {
            return Err(StoreError::Full);
        }
        let index = (0..slot_count(self.storage.key_slots()))
            .find(|&slot| self.key_is_free(slot))
            .ok_or(StoreError::Full)?;
        let mut tag = [0u8; SLOT_TAG_LEN];
        crypto.random(&mut tag);
        let mut record = Zeroizing::new([0u8; KEY_SLOT_LEN]);
        record[KEY_STATE] = USED;
        write_u32(&mut record[..], KEY_GENERATION, self.generation);
        write_u16(&mut record[..], KEY_OWNER_SLOT, owner.id.slot);
        write_u32(&mut record[..], KEY_OWNER_SEQUENCE, owner.id.sequence);
        record[KEY_TAG..KEY_PRIVATE].copy_from_slice(&tag);
        record[KEY_PRIVATE..KEY_CRED_RANDOM_UV].copy_from_slice(&key.private_key[..]);
        record[KEY_CRED_RANDOM_UV..KEY_CRED_RANDOM].copy_from_slice(&key.cred_random_uv[..]);
        record[KEY_CRED_RANDOM..].copy_from_slice(&key.cred_random[..]);
        self.storage.write_key_slot(usize::from(index), &record);
        Ok(KeySource::Slot { index, tag })
    }

    /// Writes the entry of `reservation` with its credential ID, replacing the entry that was in
    /// the slot; a device-only key of the replaced entry is wiped.
    ///
    /// # Errors
    ///
    /// [`StoreError::TooLong`] for a credential ID over the maximum length or empty,
    /// [`StoreError::Stale`] for a reservation made before a reset. The reservation is
    /// released then.
    pub fn commit(
        &mut self,
        reservation: Reservation,
        credential_id: &[u8],
    ) -> Result<EntryId, StoreError> {
        if reservation.generation != self.generation {
            return Err(StoreError::Stale);
        }
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            self.release(reservation);
            return Err(StoreError::TooLong);
        }
        let id = reservation.id;
        let rp_id_len = usize::from(reservation.rp_id_len);
        let mut record = [0u8; INDEX_ENTRY_LEN];
        record[ENTRY_STATE] = USED;
        write_u32(&mut record, ENTRY_GENERATION, self.generation);
        write_u32(&mut record, ENTRY_SEQUENCE, id.sequence);
        record[ENTRY_RP_ID_HASH..ENTRY_RP_ID_LEN].copy_from_slice(&reservation.rp_id_hash);
        record[ENTRY_RP_ID_LEN] = reservation.rp_id_len;
        record[ENTRY_RP_ID..ENTRY_RP_ID + rp_id_len]
            .copy_from_slice(&reservation.rp_id[..rp_id_len]);
        // At most MAX_CREDENTIAL_ID_LEN, checked above, which fits in 16 bits.
        let length = u16::try_from(credential_id.len()).map_err(|_| StoreError::TooLong)?;
        write_u16(&mut record, ENTRY_CREDENTIAL_ID_LEN, length);
        record[ENTRY_CREDENTIAL_ID..ENTRY_CREDENTIAL_ID + credential_id.len()]
            .copy_from_slice(credential_id);
        self.storage
            .write_index_entry(usize::from(id.slot), &record);
        self.wipe_orphans(id.slot);
        Ok(id)
    }

    /// Gives up a reservation, wiping the key stored for it. A reservation made before a reset has
    /// nothing left to wipe: the reset retired its key, and a newer reservation of the same index
    /// slot may be waiting with its own.
    pub fn release(&mut self, reservation: Reservation) {
        if reservation.generation != self.generation {
            return;
        }
        let owner = reservation.id;
        for key in 0..slot_count(self.storage.key_slots()) {
            let record = self.storage.key_slot(usize::from(key));
            let owned = record[KEY_STATE] == USED
                && read_u32(record, KEY_GENERATION) == self.generation
                && read_u16(record, KEY_OWNER_SLOT) == owner.slot
                && read_u32(record, KEY_OWNER_SEQUENCE) == owner.sequence;
            if owned {
                self.storage
                    .write_key_slot(usize::from(key), &[0; KEY_SLOT_LEN]);
            }
        }
    }

    /// Removes the entry `id` and wipes its device-only key; `false` when the index no longer
    /// holds that entry.
    pub fn remove(&mut self, id: EntryId) -> bool {
        if self.entry(id.slot).map(|entry| entry.id) != Some(id) {
            return false;
        }
        self.storage
            .write_index_entry(usize::from(id.slot), &[0; INDEX_ENTRY_LEN]);
        self.wipe_orphans(id.slot);
        true
    }

    /// The secrets in key slot `index` if the slot still holds the key created with `tag` and its
    /// entry is still in the index.
    pub fn key(&self, index: u16, tag: &[u8; SLOT_TAG_LEN]) -> Option<DeviceKey> {
        if index >= slot_count(self.storage.key_slots()) || !self.key_is_live(index) {
            return None;
        }
        let record = self.storage.key_slot(usize::from(index));
        if !constant_time_eq(&record[KEY_TAG..KEY_PRIVATE], tag) {
            return None;
        }
        let part = |at: usize| {
            let mut value = Zeroizing::new([0u8; KEY_LEN]);
            value.copy_from_slice(&record[at..at + KEY_LEN]);
            value
        };
        Some(DeviceKey {
            private_key: part(KEY_PRIVATE),
            cred_random_uv: part(KEY_CRED_RANDOM_UV),
            cred_random: part(KEY_CRED_RANDOM),
        })
    }

    /// Whether a live key of this generation belongs to the entry `id`.
    fn owns_key(&self, id: EntryId) -> bool {
        (0..slot_count(self.storage.key_slots())).any(|key| {
            let record = self.storage.key_slot(usize::from(key));
            self.key_is_live(key)
                && read_u16(record, KEY_OWNER_SLOT) == id.slot
                && read_u32(record, KEY_OWNER_SEQUENCE) == id.sequence
        })
    }

    /// Whether the key slot is free: not in use, or written under an earlier generation. A key
    /// of this generation counts as taken, also while it waits for its entry.
    fn key_is_free(&self, slot: u16) -> bool {
        let record = self.storage.key_slot(usize::from(slot));
        record[KEY_STATE] != USED || read_u32(record, KEY_GENERATION) != self.generation
    }

    /// A key of this generation whose owner entry is in the index.
    fn key_is_live(&self, slot: u16) -> bool {
        if self.key_is_free(slot) {
            return false;
        }
        let record = self.storage.key_slot(usize::from(slot));
        let owner = EntryId {
            slot: read_u16(record, KEY_OWNER_SLOT),
            sequence: read_u32(record, KEY_OWNER_SEQUENCE),
        };
        owner.slot < slot_count(self.storage.index_slots())
            && self.entry(owner.slot).map(|entry| entry.id) == Some(owner)
    }

    /// Wipes the keys owned by index slot `slot` that its current entry does not own.
    fn wipe_orphans(&mut self, slot: u16) {
        for key in 0..slot_count(self.storage.key_slots()) {
            let record = self.storage.key_slot(usize::from(key));
            let owned_here = record[KEY_STATE] == USED && read_u16(record, KEY_OWNER_SLOT) == slot;
            if owned_here && !self.key_is_live(key) {
                self.storage
                    .write_key_slot(usize::from(key), &[0; KEY_SLOT_LEN]);
            }
        }
    }

    /// Wipes every record that is not live (an earlier generation, an orphaned key, a malformed
    /// entry) and is not already zero, and finds the next creation sequence.
    fn sweep(&mut self) {
        let mut newest = None;
        for slot in 0..self.storage.index_slots() {
            let live = u16::try_from(slot)
                .ok()
                .and_then(|slot| self.entry(slot))
                .map(|entry| entry.id.sequence);
            match live {
                Some(sequence) => newest = newest.max(Some(sequence)),
                None => {
                    if !is_zero(self.storage.index_entry(slot)) {
                        self.storage.write_index_entry(slot, &[0; INDEX_ENTRY_LEN]);
                    }
                }
            }
        }
        for slot in 0..self.storage.key_slots() {
            let live = u16::try_from(slot).is_ok_and(|slot| self.key_is_live(slot));
            if !live && !is_zero(self.storage.key_slot(slot)) {
                self.storage.write_key_slot(slot, &[0; KEY_SLOT_LEN]);
            }
        }
        // Every sequence below the recorded limit may have been handed out already.
        let after_newest = newest.map_or(0, |sequence| u64::from(sequence) + 1);
        self.next_sequence = after_newest.max(u64::from(self.sequence_limit));
    }
}

#[cfg(test)]
mod tests;

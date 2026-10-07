//! [`Storage`] in RAM for host tests and fuzzing, with simulated power loss.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

use super::{CONFIG_LEN, INDEX_ENTRY_LEN, KEY_SLOT_LEN, NAME_SLOT_LEN, NAME_SLOTS, Storage};

/// NVM regions held in RAM. Writes are atomic per record, as on the device; after
/// [`MemoryStorage::lose_power_after`] the given number of writes land and every later one is
/// lost, until [`MemoryStorage::power_on`]. Key slots are zeroized on drop, and the `Debug`
/// output shows no record: they hold keys and the PIN verifier.
#[derive(Clone)]
pub struct MemoryStorage {
    config: [u8; CONFIG_LEN],
    index: Vec<[u8; INDEX_ENTRY_LEN]>,
    keys: Vec<[u8; KEY_SLOT_LEN]>,
    names: Vec<[u8; NAME_SLOT_LEN]>,
    writes: usize,
    power_until: Option<usize>,
}

impl MemoryStorage {
    /// Fresh NVM, all zeros, with `index_slots` discoverable slots, `key_slots` key slots and the
    /// device's [`NAME_SLOTS`] name override slots.
    pub fn new(index_slots: usize, key_slots: usize) -> Self {
        Self::with_name_slots(index_slots, key_slots, NAME_SLOTS)
    }

    /// Fresh NVM as [`MemoryStorage::new`], with `name_slots` name override slots.
    pub fn with_name_slots(index_slots: usize, key_slots: usize, name_slots: usize) -> Self {
        Self {
            config: [0; CONFIG_LEN],
            index: vec![[0; INDEX_ENTRY_LEN]; index_slots],
            keys: vec![[0; KEY_SLOT_LEN]; key_slots],
            names: vec![[0; NAME_SLOT_LEN]; name_slots],
            writes: 0,
            power_until: None,
        }
    }

    /// Lets `writes` more writes land and loses every one after them; an allowance past the
    /// write counter's range never cuts power. Once power is lost, it stays lost until
    /// [`MemoryStorage::power_on`], whatever later limit is set.
    pub fn lose_power_after(&mut self, writes: usize) {
        if self.power_until.is_some_and(|until| self.writes >= until) {
            return;
        }
        self.power_until = self.writes.checked_add(writes);
    }

    /// Restores power: later writes land again.
    pub fn power_on(&mut self) {
        self.power_until = None;
    }

    /// Writes that landed so far.
    pub const fn writes(&self) -> usize {
        self.writes
    }

    /// Whether the next write lands, counting it if it does.
    fn powered(&mut self) -> bool {
        if self.power_until.is_some_and(|until| self.writes >= until) {
            return false;
        }
        self.writes += 1;
        true
    }
}

impl fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryStorage")
            .field("index_slots", &self.index.len())
            .field("key_slots", &self.keys.len())
            .field("writes", &self.writes)
            .field("power_until", &self.power_until)
            .finish_non_exhaustive()
    }
}

impl Drop for MemoryStorage {
    fn drop(&mut self) {
        for slot in &mut self.keys {
            slot.zeroize();
        }
        self.config.zeroize();
    }
}

impl Storage for MemoryStorage {
    fn config(&self) -> &[u8; CONFIG_LEN] {
        &self.config
    }

    fn write_config(&mut self, record: &[u8; CONFIG_LEN]) {
        if self.powered() {
            self.config = *record;
        }
    }

    fn index_slots(&self) -> usize {
        self.index.len()
    }

    fn index_entry(&self, slot: usize) -> &[u8; INDEX_ENTRY_LEN] {
        &self.index[slot]
    }

    fn write_index_entry(&mut self, slot: usize, record: &[u8; INDEX_ENTRY_LEN]) {
        if self.powered() {
            self.index[slot] = *record;
        }
    }

    fn key_slots(&self) -> usize {
        self.keys.len()
    }

    fn key_slot(&self, slot: usize) -> &[u8; KEY_SLOT_LEN] {
        &self.keys[slot]
    }

    fn write_key_slot(&mut self, slot: usize, record: &[u8; KEY_SLOT_LEN]) {
        if self.powered() {
            self.keys[slot] = *record;
        }
    }

    fn name_slots(&self) -> usize {
        self.names.len()
    }

    fn name_slot(&self, slot: usize) -> &[u8; NAME_SLOT_LEN] {
        &self.names[slot]
    }

    fn write_name_slot(&mut self, slot: usize, record: &[u8; NAME_SLOT_LEN]) {
        if self.powered() {
            self.names[slot] = *record;
        }
    }
}

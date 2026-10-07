//! The NVM regions of [`Storage`] as statics in the application's `.nvm_data`, each record an SDK
//! [`AtomicStorage`]: two copies with validity flags, so after a power loss a record holds the
//! value before a write or the value written. An update writes the other copy and only
//! invalidates the current one, whose bytes stay; every record is therefore settled after every
//! write and at start, so both copies hold the current value and no retired key, PIN verifier,
//! RP ID or credential ID is left, also after a power loss between the two writes.

use ledger_device_sdk::NVMData;
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use structured_passkeys_ctap::storage::{
    CONFIG_LEN, INDEX_ENTRY_LEN, KEY_SLOT_LEN, NAME_SLOT_LEN, NAME_SLOTS, Storage,
};

/// Discoverable index slots: at least 64 on every device.
pub const INDEX_SLOTS: usize = 64;
/// Device-only key slots: one per index slot, so every discoverable credential can be
/// device-only, plus the spare a replacement writes its new key into before the old one goes.
pub const KEY_SLOTS: usize = INDEX_SLOTS + 1;

type Record<const N: usize> = AtomicStorage<[u8; N]>;

// A fresh install holds all-zero records, which the store formats on open.
#[unsafe(link_section = ".nvm_data")]
static mut CONFIG: NVMData<Record<CONFIG_LEN>> = NVMData::new(AtomicStorage::new(&[0; CONFIG_LEN]));
#[unsafe(link_section = ".nvm_data")]
static mut INDEX: NVMData<[Record<INDEX_ENTRY_LEN>; INDEX_SLOTS]> =
    NVMData::new([const { AtomicStorage::new(&[0; INDEX_ENTRY_LEN]) }; INDEX_SLOTS]);
#[unsafe(link_section = ".nvm_data")]
static mut KEYS: NVMData<[Record<KEY_SLOT_LEN>; KEY_SLOTS]> =
    NVMData::new([const { AtomicStorage::new(&[0; KEY_SLOT_LEN]) }; KEY_SLOTS]);
#[unsafe(link_section = ".nvm_data")]
static mut NAMES: NVMData<[Record<NAME_SLOT_LEN>; NAME_SLOTS]> =
    NVMData::new([const { AtomicStorage::new(&[0; NAME_SLOT_LEN]) }; NAME_SLOTS]);

/// The application's NVM regions.
pub struct NvmStorage {
    config: &'static mut Record<CONFIG_LEN>,
    index: &'static mut [Record<INDEX_ENTRY_LEN>; INDEX_SLOTS],
    keys: &'static mut [Record<KEY_SLOT_LEN>; KEY_SLOTS],
    names: &'static mut [Record<NAME_SLOT_LEN>; NAME_SLOTS],
}

impl NvmStorage {
    /// The regions, through the PIC-translated addresses of the statics. A record that was
    /// never written (Speculos loads `.nvm_data` zeroed, validity flags included) is written
    /// as zeros, the free record, so every later read finds a valid copy. Every record is
    /// settled, finishing an erase a power loss interrupted.
    ///
    /// # Safety
    ///
    /// Called at most once: the returned value holds the only references to the statics.
    pub unsafe fn take() -> Self {
        let config = &raw mut CONFIG;
        let index = &raw mut INDEX;
        let keys = &raw mut KEYS;
        let names = &raw mut NAMES;
        // SAFETY: the caller takes the statics once, so these are their only references.
        let storage = unsafe {
            Self {
                config: (*config).get_mut(),
                index: (*index).get_mut(),
                keys: (*keys).get_mut(),
                names: (*names).get_mut(),
            }
        };
        storage.config.get_or_init(&[0; CONFIG_LEN]);
        storage.config.settle();
        for record in storage.index.iter_mut() {
            record.get_or_init(&[0; INDEX_ENTRY_LEN]);
            record.settle();
        }
        for record in storage.keys.iter_mut() {
            record.get_or_init(&[0; KEY_SLOT_LEN]);
            record.settle();
        }
        for record in storage.names.iter_mut() {
            record.get_or_init(&[0; NAME_SLOT_LEN]);
            record.settle();
        }
        storage
    }
}

impl Storage for NvmStorage {
    fn config(&self) -> &[u8; CONFIG_LEN] {
        self.config.get_ref()
    }

    fn write_config(&mut self, record: &[u8; CONFIG_LEN]) {
        // The PIN verifier: settling overwrites the copy the update retired.
        self.config.update(record);
        self.config.settle();
    }

    fn index_slots(&self) -> usize {
        INDEX_SLOTS
    }

    fn index_entry(&self, slot: usize) -> &[u8; INDEX_ENTRY_LEN] {
        self.index[slot].get_ref()
    }

    fn write_index_entry(&mut self, slot: usize, record: &[u8; INDEX_ENTRY_LEN]) {
        // RP ID and credential ID of a removed or reset entry: settling overwrites the copy the
        // update retired.
        self.index[slot].update(record);
        self.index[slot].settle();
    }

    fn key_slots(&self) -> usize {
        KEY_SLOTS
    }

    fn key_slot(&self, slot: usize) -> &[u8; KEY_SLOT_LEN] {
        self.keys[slot].get_ref()
    }

    fn write_key_slot(&mut self, slot: usize, record: &[u8; KEY_SLOT_LEN]) {
        // Private key and CredRandom: settling overwrites the copy the update retired.
        self.keys[slot].update(record);
        self.keys[slot].settle();
    }

    fn name_slots(&self) -> usize {
        NAME_SLOTS
    }

    fn name_slot(&self, slot: usize) -> &[u8; NAME_SLOT_LEN] {
        self.names[slot].get_ref()
    }

    fn write_name_slot(&mut self, slot: usize, record: &[u8; NAME_SLOT_LEN]) {
        // Sealed names of a removed entry: settling overwrites the copy the update retired.
        self.names[slot].update(record);
        self.names[slot].settle();
    }
}

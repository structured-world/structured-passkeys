//! The store over the in-memory double: layout, index order and replacement, device-only keys,
//! reset, capacity, and power loss at every write of every operation.

use zeroize::Zeroizing;

use super::{
    Config, DeviceKey, EntryId, INDEX_ENTRY_LEN, KEY_SLOT_LEN, KEY_TAG, LAYOUT_VERSION,
    MAX_RP_ID_LEN, MAX_SEALED_NAMES_LEN, MemoryStorage, NAME_SLOT_LEN, PIN_RETRIES, PinVerifier,
    Storage, Store, StoreError,
};
use crate::credential_id::{KeySource, MAX_CREDENTIAL_ID_LEN, SLOT_TAG_LEN};
use crate::crypto::KEY_LEN;
use crate::ctap2::StatusCode;
use crate::soft::SoftCrypto;

const RP_A: [u8; KEY_LEN] = [0xA0; KEY_LEN];
const RP_B: [u8; KEY_LEN] = [0xB0; KEY_LEN];

fn crypto() -> SoftCrypto {
    SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN])
}

fn device_key(fill: u8) -> DeviceKey {
    DeviceKey {
        private_key: Zeroizing::new([fill; KEY_LEN]),
        cred_random_uv: Zeroizing::new([fill ^ 0x0F; KEY_LEN]),
        cred_random: Zeroizing::new([fill ^ 0xF0; KEY_LEN]),
    }
}

/// Test credential IDs are `user:n`; the stored ID tells the user, as opening a real one does.
fn same_user(user: &'static str) -> impl FnMut(&super::IndexEntry<'_>) -> bool {
    move |entry| entry.credential_id.split(|&b| b == b':').next() == Some(user.as_bytes())
}

/// Adds a discoverable credential, device-only when `key` is given.
fn add(
    store: &mut Store<MemoryStorage>,
    crypto: &mut SoftCrypto,
    rp: &[u8; KEY_LEN],
    user: &'static str,
    id: &str,
    key: Option<&DeviceKey>,
) -> Result<(EntryId, Option<KeySource>), StoreError> {
    let reservation = store.reserve(rp, "example.com", same_user(user))?;
    let source = match key {
        Some(key) => match store.store_key(crypto, &reservation, key) {
            Ok(source) => Some(source),
            Err(error) => {
                store.release(reservation);
                return Err(error);
            }
        },
        None => None,
    };
    let credential_id = format!("{user}:{id}");
    let entry = store.commit(reservation, credential_id.as_bytes())?;
    Ok((entry, source))
}

fn slot_key(source: &KeySource) -> (u16, [u8; SLOT_TAG_LEN]) {
    match source {
        KeySource::Slot { index, tag } => (*index, *tag),
        KeySource::Seed(_) | KeySource::Device(_) => panic!("a stored key is a slot"),
    }
}

/// Everything a caller can observe: configuration, entries newest first, live keys.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    reset_id: u32,
    always_uv: bool,
    pin: Option<[u8; 16]>,
    pin_retries: u8,
    device_key: Option<[u8; KEY_LEN]>,
    entries: Vec<Observed>,
    keys: Vec<(u16, [u8; KEY_LEN])>,
}

/// An entry as a caller sees it, with its sealed name override.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    rp_id_hash: Vec<u8>,
    rp_id: String,
    credential_id: Vec<u8>,
    names: Option<Vec<u8>>,
}

fn snapshot(store: &Store<MemoryStorage>) -> Snapshot {
    let config = store.config();
    let mut entries: Vec<_> = store.entries().collect();
    entries.sort_unstable_by_key(|entry| core::cmp::Reverse(entry.id.sequence));
    let keys = (0..u16::try_from(store.storage.key_slots()).expect("few slots"))
        .filter_map(|index| {
            let record = store.storage.key_slot(usize::from(index));
            let tag: [u8; SLOT_TAG_LEN] = record[KEY_TAG..KEY_TAG + SLOT_TAG_LEN]
                .try_into()
                .expect("tag field");
            store.key(index, &tag).map(|key| (index, *key.private_key))
        })
        .collect();
    Snapshot {
        reset_id: config.reset_id,
        always_uv: config.always_uv,
        pin: config.pin.as_ref().map(|pin| pin.0),
        pin_retries: config.pin_retries,
        device_key: store.device_key().map(|key| *key),
        entries: entries
            .iter()
            .map(|entry| Observed {
                rp_id_hash: entry.rp_id_hash.to_vec(),
                rp_id: entry.rp_id.into(),
                credential_id: entry.credential_id.to_vec(),
                names: store.names(entry.id).map(<[u8]>::to_vec),
            })
            .collect(),
        keys,
    }
}

/// Every record that holds no live entry or key is all zeros: nothing a removal, a replacement
/// or a reset retired is left in NVM.
fn assert_no_residue(store: &Store<MemoryStorage>) {
    for slot in 0..store.storage.index_slots() {
        let live = u16::try_from(slot)
            .ok()
            .and_then(|slot| store.entry(slot))
            .is_some();
        assert!(
            live || store.storage.index_entry(slot) == &[0; INDEX_ENTRY_LEN],
            "index slot {slot} keeps a retired entry"
        );
    }
    for slot in 0..store.storage.key_slots() {
        let live = u16::try_from(slot).is_ok_and(|slot| store.key_is_live(slot));
        assert!(
            live || store.storage.key_slot(slot) == &[0; KEY_SLOT_LEN],
            "key slot {slot} keeps a retired key"
        );
    }
    for slot in 0..store.storage.name_slots() {
        let live = u16::try_from(slot).is_ok_and(|slot| store.names_owner(slot).is_some());
        assert!(
            live || store.storage.name_slot(slot) == &[0; NAME_SLOT_LEN],
            "name slot {slot} keeps retired names"
        );
    }
}

/// A fresh install reads all zeros: open formats it with the configuration after a reset and
/// every slot free.
#[test]
fn fresh_nvm_is_formatted() {
    let store = Store::open(MemoryStorage::new(4, 2));
    assert_eq!(store.storage.config()[0], LAYOUT_VERSION);
    let config = store.config();
    assert_eq!(config.reset_id, 0);
    assert!(!config.always_uv);
    assert!(config.pin.is_none());
    assert_eq!(config.pin_retries, PIN_RETRIES);
    assert_eq!(store.entries().count(), 0);
    assert_eq!(
        store.remaining_discoverable(),
        1,
        "four index slots, but keys for one device-only credential"
    );
    assert_eq!(
        store.remaining_keys(),
        1,
        "one of the two is kept for replacements"
    );
}

/// NVM of another layout version is wiped, slot by slot, before the new configuration is
/// written; a power loss in the middle restarts the format on the next open.
#[test]
fn another_layout_is_wiped_even_when_interrupted() {
    let mut storage = MemoryStorage::new(3, 2);
    let mut config = [0x5A; super::CONFIG_LEN];
    config[0] = LAYOUT_VERSION + 1;
    storage.write_config(&config);
    for slot in 0..3 {
        storage.write_index_entry(slot, &[0x77; INDEX_ENTRY_LEN]);
    }
    for slot in 0..2 {
        storage.write_key_slot(slot, &[0x99; KEY_SLOT_LEN]);
    }
    // Three index slots, two key slots and the configuration: six writes. Lose power after two.
    storage.lose_power_after(2);
    let mut storage = Store::open(storage).into_storage();
    assert_eq!(storage.config()[0], LAYOUT_VERSION + 1, "not formatted yet");
    storage.power_on();
    let store = Store::open(storage);
    assert_eq!(store.storage.config()[0], LAYOUT_VERSION);
    assert_eq!(store.config().reset_id, 0);
    assert_eq!(store.entries().count(), 0);
    assert_eq!(store.remaining_keys(), 1);
    assert_no_residue(&store);
}

/// The configuration round-trips, the PIN verifier included, and the verifier compares equal
/// only to itself.
#[test]
fn the_configuration_round_trips() {
    let mut store = Store::open(MemoryStorage::new(1, 1));
    store.write_config(&Config {
        reset_id: 0,
        always_uv: true,
        pin: Some(PinVerifier::new([0x42; 16])),
        pin_retries: 5,
    });
    let store = Store::open(store.into_storage());
    let config = store.config();
    assert!(config.always_uv);
    assert_eq!(config.pin_retries, 5);
    let pin = config.pin.expect("a PIN is set");
    assert!(pin.matches(&[0x42; 16]));
    assert!(!pin.matches(&[0x43; 16]));
    assert_eq!(format!("{pin:?}"), "PinVerifier(<redacted>)");
}

/// A configuration write built from a stale or constructed `Config` keeps the stored reset ID,
/// whatever it carries: only a reset changes it, and bringing back a replaced one, or 0, would
/// open the credential IDs that reset revoked. The rest of the configuration is written as given.
#[test]
fn a_configuration_write_keeps_the_reset_id() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 1));
    store
        .reset(&mut crypto)
        .expect("counters far from wrapping");
    let reset_id = store.config().reset_id;
    for stale in [0, reset_id.wrapping_add(1)] {
        store.write_config(&Config {
            reset_id: stale,
            always_uv: true,
            pin: Some(PinVerifier::new([0x42; 16])),
            pin_retries: 4,
        });
    }
    let store = Store::open(store.into_storage());
    let config = store.config();
    assert_eq!(config.reset_id, reset_id);
    assert!(config.always_uv);
    assert_eq!(config.pin_retries, 4);
    assert!(config.pin.expect("a PIN is set").matches(&[0x42; 16]));
}

/// Entries of an RP come back most recently created first (CTAP 2.2 §6.2.2), also after a
/// reopen, which continues the creation sequence; another RP's entries are not among them.
#[test]
fn entries_come_newest_first() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(4, 0));
    add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    add(&mut store, &mut crypto, &RP_B, "bob", "1", None).expect("room");
    add(&mut store, &mut crypto, &RP_A, "carol", "1", None).expect("room");
    let mut store = Store::open(store.into_storage());
    add(&mut store, &mut crypto, &RP_A, "dave", "1", None).expect("room");
    let ids: Vec<_> = store
        .newest_first(&RP_A)
        .iter()
        .map(|entry| entry.credential_id.to_vec())
        .collect();
    assert_eq!(
        ids,
        [&b"dave:1"[..], b"carol:1", b"alice:1"].map(<[u8]>::to_vec)
    );
    assert_eq!(store.remaining_discoverable(), 0);
}

/// A new credential for a user the RP already has replaces that entry in its slot (CTAP 2.2
/// §6.1.2 step 17.2), even when the index is full; the same user at another RP is another
/// credential.
#[test]
fn the_same_user_is_replaced_even_when_full() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 0));
    let (first, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    add(&mut store, &mut crypto, &RP_B, "alice", "1", None).expect("room");
    let (second, _) = add(&mut store, &mut crypto, &RP_A, "alice", "2", None).expect("replaces");
    assert_eq!(second.slot, first.slot);
    assert!(second.sequence > first.sequence);
    let ids: Vec<_> = store
        .newest_first(&RP_A)
        .iter()
        .map(|entry| entry.credential_id.to_vec())
        .collect();
    assert_eq!(ids, [b"alice:2".to_vec()]);
    assert_eq!(store.newest_first(&RP_B).len(), 1);
}

/// A full index refuses a new user with KEY_STORE_FULL and writes nothing.
#[test]
fn a_full_index_refuses_a_new_user() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 0));
    add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    let writes = store.storage.writes();
    let refused = store.reserve(&RP_A, "example.com", same_user("bob"));
    assert_eq!(
        refused.map(|reservation| reservation.id()),
        Err(StoreError::Full)
    );
    assert_eq!(StatusCode::from(StoreError::Full), StatusCode::KeyStoreFull);
    assert_eq!(store.storage.writes(), writes);
}

/// The RP ID an entry keeps for `rp_id`.
fn stored(rp_id: &str) -> String {
    let mut store = Store::open(MemoryStorage::new(1, 0));
    let reservation = store
        .reserve(&RP_A, rp_id, same_user("alice"))
        .expect("room");
    store
        .commit(reservation, b"alice:1")
        .expect("an ID within bounds");
    let entry = store.entry(0).expect("alice");
    assert_eq!(entry.rp_id_hash, &RP_A, "the hash stays the full RP ID's");
    entry.rp_id.into()
}

/// RP IDs up to 64 bytes are kept whole; a longer one is kept in the form of CTAP 2.2 §6.8.7
/// (its procedure with 64 bytes in place of 32): the protocol up to the first colon, U+2026, then
/// the end of the RP ID, so RP IDs that differ only at the end stay apart.
#[test]
fn long_rp_ids_are_truncated_as_ctap_specifies() {
    let longest = "a".repeat(MAX_RP_ID_LEN);
    assert_eq!(stored(&longest), longest);

    let domain = format!("{}.hostingprovider.example.net", "w".repeat(60));
    assert_eq!(
        stored(&domain),
        format!("…{}", &domain[domain.len() - (MAX_RP_ID_LEN - 3)..])
    );

    let other = format!("otherprotocol://{}.example", "y".repeat(70));
    assert_eq!(
        stored(&other),
        format!(
            "otherprotocol:…{}",
            &other[other.len() - (MAX_RP_ID_LEN - 14 - 3)..]
        )
    );

    // A protocol that leaves no room for the ellipsis is kept alone, cut to the limit.
    let protocol = format!("{}://example.com", "p".repeat(70));
    assert_eq!(stored(&protocol), "p".repeat(MAX_RP_ID_LEN));
    let protocol = format!("{}://{}", "q".repeat(MAX_RP_ID_LEN - 2), "z".repeat(10));
    assert_eq!(
        stored(&protocol),
        format!("{}:", "q".repeat(MAX_RP_ID_LEN - 2))
    );
}

/// Where the procedure's byte offsets fall inside a UTF-8 character, the cut moves to the
/// character boundary that keeps the stored RP ID text: the end starts one character later, the
/// protocol stops one character earlier.
#[test]
fn rp_id_truncation_keeps_whole_characters() {
    // 80 bytes of two-byte characters: the last 61 bytes would start inside one.
    assert_eq!(stored(&"é".repeat(40)), format!("…{}", "é".repeat(30)));
    // A protocol of 1 + 80 bytes cut at 64 would split the 32nd character.
    assert_eq!(
        stored(&format!("a{}:x", "é".repeat(40))),
        format!("a{}", "é".repeat(31))
    );
}

/// A credential ID over the maximum length or empty is refused at commit, and the reservation's
/// key is wiped with it.
#[test]
fn oversized_credential_ids_are_refused() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    for id in [vec![0x01; MAX_CREDENTIAL_ID_LEN + 1], Vec::new()] {
        let reservation = store
            .reserve(&RP_A, "example.com", same_user("alice"))
            .expect("room");
        store
            .store_key(&mut crypto, &reservation, &device_key(1))
            .expect("a free key slot");
        assert_eq!(store.commit(reservation, &id), Err(StoreError::TooLong));
        assert_eq!(store.remaining_discoverable(), 1);
        assert_eq!(store.remaining_keys(), 1);
        assert_no_residue(&store);
    }
}

/// A device-only key opens with its slot and tag once its entry is committed; before that, with
/// another tag, or in another slot it does not.
#[test]
fn a_device_key_opens_only_with_its_tag_and_entry() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 2));
    let reservation = store
        .reserve(&RP_A, "example.com", same_user("alice"))
        .expect("room");
    let source = store
        .store_key(&mut crypto, &reservation, &device_key(0x31))
        .expect("a free key slot");
    let (index, tag) = slot_key(&source);
    assert!(store.key(index, &tag).is_none(), "not before the entry");
    store.commit(reservation, b"alice:1").expect("room");
    let key = store.key(index, &tag).expect("the committed key");
    assert_eq!(*key.private_key, [0x31; KEY_LEN]);
    assert_eq!(*key.cred_random_uv, [0x31 ^ 0x0F; KEY_LEN]);
    assert_eq!(*key.cred_random, [0x31 ^ 0xF0; KEY_LEN]);
    assert_eq!(format!("{key:?}"), "DeviceKey(<redacted>)");
    let mut wrong = tag;
    wrong[0] ^= 1;
    assert!(store.key(index, &wrong).is_none());
    assert!(store.key(index + 1, &tag).is_none());
    assert!(store.key(u16::MAX, &tag).is_none());
}

/// The device key of non-discoverable device-only credentials is drawn once, at the first such
/// credential, and kept across reopens and configuration writes; it takes no key slot.
#[test]
fn the_device_key_is_created_once_and_kept() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    assert!(store.device_key().is_none(), "none before the first");
    let created = store.device_key_or_create(&mut crypto);
    assert_eq!(*store.device_key_or_create(&mut crypto), *created);
    store.write_config(&Config {
        pin: Some(PinVerifier::new([7; 16])),
        ..store.config()
    });
    let store = Store::open(store.into_storage());
    assert_eq!(store.device_key().as_deref(), Some(&*created));
    assert_eq!(store.remaining_keys(), 1, "no key slot taken");
}

/// Reset erases the device key with the rest of the configuration (CTAP 2.2 §6.6), so every
/// non-discoverable device-only credential stops opening; the next one gets a new key.
#[test]
fn reset_erases_the_device_key() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    let before = store.device_key_or_create(&mut crypto);
    store.reset(&mut crypto).expect("a generation left");
    assert!(store.device_key().is_none());
    let store_after = Store::open(store.into_storage());
    assert!(store_after.device_key().is_none(), "also after a reopen");
    let mut store = store_after;
    assert_ne!(*store.device_key_or_create(&mut crypto), *before);
}

/// Formatting NVM of another layout keeps no device key and no store ID from its bytes.
#[test]
fn another_layout_leaves_no_device_key() {
    let mut storage = MemoryStorage::new(1, 1);
    let mut config = [0xA5; super::CONFIG_LEN];
    config[0] = LAYOUT_VERSION + 1;
    storage.write_config(&config);
    let store = Store::open(storage);
    assert!(store.device_key().is_none());
    assert!(store.store_id().is_none());
}

/// The store ID is drawn at the first discoverable credential of a formatted NVM, nonzero, and
/// kept across reopens, configuration writes, a device key creation and a reset: the reset ID
/// revokes what came before a reset, and the store ID tells this NVM's credentials from those of
/// another install. A device key write or a PIN write never erases it.
#[test]
fn the_store_id_is_created_once_and_kept() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    assert!(store.store_id().is_none(), "none before the first");
    let created = store.store_id_or_create(&mut crypto);
    assert_ne!(created.get(), 0);
    assert_eq!(store.store_id_or_create(&mut crypto), created);
    store.write_config(&Config {
        pin: Some(PinVerifier::new([7; 16])),
        ..store.config()
    });
    store.device_key_or_create(&mut crypto);
    assert_eq!(store.store_id(), Some(created));
    store.reset(&mut crypto).expect("a generation left");
    let store = Store::open(store.into_storage());
    assert_eq!(store.store_id(), Some(created));
}

/// A reused slot gets a new tag, so the ID of the credential that held it no longer opens it.
#[test]
fn a_reused_key_slot_has_a_new_tag() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    let (entry, old) = add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    assert!(store.remove(entry));
    let (_, new) = add(
        &mut store,
        &mut crypto,
        &RP_A,
        "bob",
        "1",
        Some(&device_key(2)),
    )
    .expect("room");
    let (old_index, old_tag) = slot_key(&old.expect("device-only"));
    let (new_index, new_tag) = slot_key(&new.expect("device-only"));
    assert_eq!(old_index, new_index);
    assert_ne!(old_tag, new_tag);
    assert!(store.key(old_index, &old_tag).is_none());
}

/// Full key slots refuse another device-only key with KEY_STORE_FULL. The last free slot is
/// kept for replacing a device-only credential, so a new one is refused when only it is left.
#[test]
fn full_key_slots_are_refused() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 2));
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    let refused = add(
        &mut store,
        &mut crypto,
        &RP_A,
        "bob",
        "1",
        Some(&device_key(2)),
    );
    assert_eq!(refused, Err(StoreError::Full));
    assert_eq!(store.entries().count(), 1, "the reservation was released");
    assert_eq!(
        store.remaining_discoverable(),
        0,
        "a device-only credential would not fit"
    );
    assert_eq!(store.remaining_keys(), 0, "the free slot is the spare");
}

/// `remainingDiscoverableCredentials` is zero whenever a new discoverable credential may fail
/// for lack of space (CTAP 2.2 §6.4, member 0x14): with free index slots but no key slot for a
/// device-only one, it is zero.
#[test]
fn remaining_discoverable_counts_key_slots_too() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(4, 3));
    assert_eq!(store.remaining_discoverable(), 2, "two keys and the spare");
    for (user, fill) in [("alice", 1), ("bob", 2)] {
        add(
            &mut store,
            &mut crypto,
            &RP_A,
            user,
            "1",
            Some(&device_key(fill)),
        )
        .expect("room");
    }
    assert_eq!(store.entries().count(), 2, "two index slots still free");
    assert_eq!(store.remaining_discoverable(), 0);
}

/// Releasing a reservation made before a reset leaves alone the key a newer reservation of the
/// same index slot is waiting with, so that credential opens once committed.
#[test]
fn a_stale_release_keeps_a_newer_reservations_key() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 3));
    let stale = store
        .reserve(&RP_A, "example.com", same_user("alice"))
        .expect("room");
    store
        .store_key(&mut crypto, &stale, &device_key(1))
        .expect("a key slot");
    store.reset(&mut crypto).expect("a generation left");
    let fresh = store
        .reserve(&RP_A, "example.com", same_user("bob"))
        .expect("room");
    assert_eq!(fresh.id().slot, stale.id().slot);
    let source = store
        .store_key(&mut crypto, &fresh, &device_key(2))
        .expect("a key slot");
    store.release(stale);
    store.commit(fresh, b"bob:1").expect("an ID within bounds");
    let (index, tag) = slot_key(&source);
    let key = store.key(index, &tag).expect("the committed key opens");
    assert_eq!(*key.private_key, [2; KEY_LEN]);
}

/// With every key slot but the spare taken by device-only credentials, a new credential for an
/// existing user still replaces its own (CTAP 2.2 §6.1.2 step 17.2): the old key holds its slot
/// until the new entry is written, so the replacement uses the spare.
#[test]
fn a_device_credential_is_replaced_with_all_key_slots_taken() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 3));
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    add(
        &mut store,
        &mut crypto,
        &RP_B,
        "bob",
        "1",
        Some(&device_key(2)),
    )
    .expect("room");
    assert_eq!(store.remaining_keys(), 0);
    let (_, key) = add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "2",
        Some(&device_key(3)),
    )
    .expect("the replacement uses the spare");
    let (index, tag) = slot_key(&key.expect("device-only"));
    assert_eq!(
        store.key(index, &tag).map(|key| *key.private_key),
        Some([3; KEY_LEN])
    );
    assert_eq!(
        store.remaining_keys(),
        0,
        "the old key's slot is the spare now"
    );
    assert_no_residue(&store);
}

/// Replacing a device-only credential wipes its key: the old credential ID stops working at
/// once, and its slot is free again.
#[test]
fn replacing_a_device_credential_wipes_its_key() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    let (_, old) = add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "2",
        Some(&device_key(2)),
    )
    .expect("replaces");
    let (index, tag) = slot_key(&old.expect("device-only"));
    assert!(store.key(index, &tag).is_none());
    assert_eq!(
        store.remaining_keys(),
        0,
        "one slot holds the new key, the freed one is the spare"
    );
    assert_no_residue(&store);
}

/// Removing an entry wipes it and its key; removing it again, or an entry that was since
/// replaced, does nothing.
#[test]
fn removal_wipes_the_entry_and_its_key() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 2));
    let (first, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    add(&mut store, &mut crypto, &RP_A, "alice", "2", None).expect("replaces");
    assert!(!store.remove(first), "replaced since");
    let (entry, key) = add(
        &mut store,
        &mut crypto,
        &RP_B,
        "bob",
        "1",
        Some(&device_key(3)),
    )
    .expect("room");
    assert!(store.remove(entry));
    assert!(!store.remove(entry));
    let (index, tag) = slot_key(&key.expect("device-only"));
    assert!(store.key(index, &tag).is_none());
    assert_eq!(store.remaining_discoverable(), 1);
    assert_no_residue(&store);
}

/// A released reservation leaves the state as it was: its key is wiped and the entry it would
/// have replaced stays.
#[test]
fn a_released_reservation_changes_nothing() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    let before = snapshot(&store);
    let reservation = store
        .reserve(&RP_A, "example.com", same_user("alice"))
        .expect("replaces");
    store
        .store_key(&mut crypto, &reservation, &device_key(2))
        .expect("a free key slot");
    store.release(reservation);
    assert_eq!(snapshot(&store), before);
    assert_no_residue(&store);
}

/// Reset empties the index and the key slots, erases the device key, clears the PIN and
/// alwaysUv, restores the retries and draws a nonzero reset ID; a reservation made before it is
/// refused.
#[test]
fn reset_empties_everything_and_draws_a_reset_id() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(2, 3));
    store.write_config(&Config {
        reset_id: 0,
        always_uv: true,
        pin: Some(PinVerifier::new([7; 16])),
        pin_retries: 2,
    });
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    store.device_key_or_create(&mut crypto);
    let stale = store
        .reserve(&RP_B, "example.org", same_user("bob"))
        .expect("room");
    store
        .reset(&mut crypto)
        .expect("counters far from wrapping");
    assert!(store.device_key().is_none());
    let config = store.config();
    assert_ne!(config.reset_id, 0);
    assert!(!config.always_uv);
    assert!(config.pin.is_none());
    assert_eq!(config.pin_retries, PIN_RETRIES);
    assert_eq!(store.remaining_discoverable(), 2);
    assert_eq!(store.remaining_keys(), 2);
    assert_no_residue(&store);
    assert_eq!(
        store.store_key(&mut crypto, &stale, &device_key(3)).err(),
        Some(StoreError::Stale)
    );
    assert_eq!(store.commit(stale, b"bob:1"), Err(StoreError::Stale));
}

/// Every reset draws a reset ID that is neither 0, which would open every credential ID, nor the
/// one before it, which would keep the IDs created since then open; it stays across a reopen.
#[test]
fn every_reset_draws_a_new_reset_id() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 1));
    let mut previous = store.config().reset_id;
    for _ in 0..64 {
        store
            .reset(&mut crypto)
            .expect("counters far from wrapping");
        let drawn = store.config().reset_id;
        assert_ne!(drawn, 0);
        assert_ne!(drawn, previous);
        previous = drawn;
    }
    let store = Store::open(store.into_storage());
    assert_eq!(store.config().reset_id, previous);
}

/// A slot past the index is no entry, and removing an id that names one does nothing, instead
/// of indexing past the region.
#[test]
fn slots_past_the_index_are_no_entry() {
    let mut store = Store::open(MemoryStorage::new(1, 0));
    assert!(store.entry(1).is_none());
    assert!(store.entry(u16::MAX).is_none());
    assert!(!store.remove(EntryId {
        slot: 5,
        sequence: 0
    }));
}

/// An entry id never names a later credential: creation sequences keep growing across a
/// reopen after the newest entry was removed, and across a reset.
#[test]
fn entry_ids_are_never_reused() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 0));
    let (first, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    assert!(store.remove(first));
    let mut store = Store::open(store.into_storage());
    let (second, _) = add(&mut store, &mut crypto, &RP_A, "bob", "1", None).expect("room");
    assert_eq!(second.slot, first.slot);
    assert_ne!(second, first, "a reopen does not rewind the sequence");
    store
        .reset(&mut crypto)
        .expect("counters far from wrapping");
    let (third, _) = add(&mut store, &mut crypto, &RP_A, "carol", "1", None).expect("room");
    assert!(
        third.sequence > second.sequence,
        "a reset does not rewind the sequence"
    );
}

/// After the double has lost power, a later limit does not bring it back: only `power_on` does.
#[test]
fn power_stays_lost_until_power_on() {
    let mut storage = MemoryStorage::new(1, 1);
    storage.lose_power_after(0);
    storage.lose_power_after(5);
    storage.write_config(&[1; super::CONFIG_LEN]);
    assert_eq!(storage.writes(), 0);
    assert_eq!(storage.config(), &[0; super::CONFIG_LEN]);
    storage.power_on();
    storage.write_config(&[1; super::CONFIG_LEN]);
    assert_eq!(storage.config(), &[1; super::CONFIG_LEN]);
}

/// An allowance past the write counter's range never cuts power, instead of overflowing.
#[test]
fn a_huge_power_allowance_keeps_power() {
    let mut storage = MemoryStorage::new(1, 1);
    storage.write_config(&[1; super::CONFIG_LEN]);
    storage.lose_power_after(usize::MAX);
    storage.write_config(&[2; super::CONFIG_LEN]);
    assert_eq!(storage.config(), &[2; super::CONFIG_LEN]);
}

/// The double's and the store's debug output never print a record: key slots hold private keys
/// and CredRandom, the configuration the PIN verifier and the device key.
#[test]
fn debug_output_hides_the_records() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(1, 2));
    store.write_config(&Config {
        pin: Some(PinVerifier::new([0x5A; 16])),
        ..Config::after_reset(0)
    });
    store.device_key_or_create(&mut crypto);
    add(
        &mut store,
        &mut crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(0x5A)),
    )
    .expect("room");
    let printed = format!("{store:?}");
    assert!(!printed.contains("90, 90"), "no record bytes: {printed}");
}

/// Runs `operation` on the state `setup` builds with power lost after every possible number of
/// writes; after power returns and the store reopens, the state is the one before the operation
/// or the one after it, and nothing retired is left in NVM.
fn power_loss_leaves_old_or_new(
    setup: impl Fn(&mut SoftCrypto) -> MemoryStorage,
    operation: impl Fn(&mut Store<MemoryStorage>, &mut SoftCrypto),
) {
    // The generator is deterministic: every run below draws the same tags.
    let before = snapshot(&Store::open(setup(&mut crypto())));
    let mut crypto_after = crypto();
    let mut store = Store::open(setup(&mut crypto_after));
    let start = store.storage.writes();
    operation(&mut store, &mut crypto_after);
    let writes = store.storage.writes() - start;
    let after = snapshot(&Store::open(store.into_storage()));
    assert_ne!(before, after, "the operation changes the state");
    for landed in 0..writes {
        let mut crypto = crypto();
        let mut store = Store::open(setup(&mut crypto));
        store.storage.lose_power_after(landed);
        operation(&mut store, &mut crypto);
        let mut storage = store.into_storage();
        storage.power_on();
        let reopened = Store::open(storage);
        let state = snapshot(&reopened);
        assert!(
            state == before || state == after,
            "power lost after {landed} of {writes} writes: {state:?}"
        );
        assert_no_residue(&reopened);
    }
}

/// After a reset (a nonzero reset ID): two discoverable credentials of RP A (one device-only,
/// with updated names), one of RP B, the device key and a PIN.
fn populated(crypto: &mut SoftCrypto) -> MemoryStorage {
    let mut store = Store::open(MemoryStorage::new(4, 4));
    store.reset(crypto).expect("counters far from wrapping");
    store.write_config(&Config {
        reset_id: 0,
        always_uv: true,
        pin: Some(PinVerifier::new([9; 16])),
        pin_retries: 6,
    });
    let (alice, _) = add(
        &mut store,
        crypto,
        &RP_A,
        "alice",
        "1",
        Some(&device_key(1)),
    )
    .expect("room");
    store.set_names(alice, b"alice-names").expect("a name slot");
    add(&mut store, crypto, &RP_A, "bob", "1", None).expect("room");
    add(&mut store, crypto, &RP_B, "carol", "1", None).expect("room");
    store.device_key_or_create(crypto);
    store.into_storage()
}

/// Updating names is one write of the name slot.
#[test]
fn power_loss_while_updating_names() {
    power_loss_leaves_old_or_new(populated, |store, _| {
        let bob = store
            .newest_first(&RP_A)
            .first()
            .map(|entry| entry.id)
            .expect("bob's entry");
        store.set_names(bob, b"bob-names").expect("a name slot");
    });
}

/// Updated names belong to their entry: a second update rewrites the same slot, removing or
/// replacing the entry retires them with it (they are not kept for the replacement), and names
/// for an entry no longer in the index, or longer than any sealing writes, are refused.
#[test]
fn names_follow_their_entry() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::with_name_slots(4, 4, 2));
    let (alice, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    assert_eq!(store.names(alice), None, "none before an update");
    store.set_names(alice, b"first").expect("a free slot");
    store.set_names(alice, b"second").expect("its own slot");
    assert_eq!(store.names(alice), Some(&b"second"[..]));
    let (bob, _) = add(&mut store, &mut crypto, &RP_A, "bob", "1", None).expect("room");
    store.set_names(bob, b"bob").expect("the other slot");
    assert_no_residue(&store);

    let (replaced, _) = add(&mut store, &mut crypto, &RP_A, "alice", "2", None).expect("replaces");
    assert_eq!(
        store.names(replaced),
        None,
        "a new credential starts with its own names"
    );
    assert_eq!(store.names(alice), None);
    assert_eq!(
        store.set_names(alice, b"stale"),
        Err(StoreError::Stale),
        "the replaced entry takes no names"
    );
    assert!(store.remove(bob));
    assert_eq!(store.names(bob), None);
    assert_no_residue(&store);
    assert_eq!(
        store.set_names(replaced, &[0; MAX_SEALED_NAMES_LEN + 1]),
        Err(StoreError::TooLong)
    );
}

/// With every name slot holding the names of another entry, an update is refused as
/// CTAP2_ERR_KEY_STORE_FULL (CTAP 2.2 §6.8.6 step 9), and the names already stored stay; a slot
/// freed by a removal takes the next update.
#[test]
fn full_name_slots_are_refused() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::with_name_slots(4, 4, 1));
    let (alice, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    let (bob, _) = add(&mut store, &mut crypto, &RP_A, "bob", "1", None).expect("room");
    store.set_names(alice, b"alice").expect("the slot");
    let refused = store.set_names(bob, b"bob");
    assert_eq!(refused, Err(StoreError::Full));
    assert_eq!(StatusCode::from(StoreError::Full), StatusCode::KeyStoreFull);
    assert_eq!(store.names(alice), Some(&b"alice"[..]));
    assert!(store.remove(alice));
    store.set_names(bob, b"bob").expect("the freed slot");
    assert_eq!(store.names(bob), Some(&b"bob"[..]));
}

/// A reset empties the name slots with every other slot, and a store opened again keeps the
/// names of a live entry.
#[test]
fn names_survive_a_reopen_and_not_a_reset() {
    let mut crypto = crypto();
    let mut store = Store::open(MemoryStorage::new(4, 4));
    let (alice, _) = add(&mut store, &mut crypto, &RP_A, "alice", "1", None).expect("room");
    store.set_names(alice, b"alice").expect("a slot");
    let mut store = Store::open(store.into_storage());
    assert_eq!(store.names(alice), Some(&b"alice"[..]));
    store.reset(&mut crypto).expect("a generation left");
    assert_eq!(store.names(alice), None);
    assert_no_residue(&store);
}

// Power loss is invisible to the store: each operation below runs to its end and succeeds
// whether or not its writes landed.

/// Adding writes the key, then the entry.
#[test]
fn power_loss_while_adding_a_device_credential() {
    power_loss_leaves_old_or_new(populated, |store, crypto| {
        add(store, crypto, &RP_B, "dave", "1", Some(&device_key(5))).expect("room");
    });
}

/// Replacing writes the new key, the entry over the old one, then wipes the old key.
#[test]
fn power_loss_while_replacing_a_device_credential() {
    power_loss_leaves_old_or_new(populated, |store, crypto| {
        add(store, crypto, &RP_A, "alice", "2", Some(&device_key(6))).expect("replaces");
    });
}

/// Removing wipes the entry, then its key.
#[test]
fn power_loss_while_removing_a_device_credential() {
    power_loss_leaves_old_or_new(populated, |store, _| {
        let entry = store
            .newest_first(&RP_A)
            .last()
            .map(|entry| entry.id)
            .expect("alice's entry");
        assert!(store.remove(entry));
    });
}

/// Reset writes the configuration of the next generation with a new reset ID, then wipes every
/// slot.
#[test]
fn power_loss_while_resetting() {
    power_loss_leaves_old_or_new(populated, |store, crypto| {
        store.reset(crypto).expect("counters far from wrapping");
    });
}

/// The configuration is one record.
#[test]
fn power_loss_while_writing_the_configuration() {
    power_loss_leaves_old_or_new(populated, |store, _| {
        store.write_config(&Config::after_reset(9));
    });
}

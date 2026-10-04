//! Credential IDs against bytes computed independently by `tests/vectors/derive.py` (Python
//! `cryptography`, plaintext encoded by hand from the format), and every way an ID must fail to
//! open.

use super::{
    CredProtect, Credential, KeySource, MAX_CREDENTIAL_ID_LEN, MAX_NAME_LEN, MAX_USER_ID_LEN,
    OpenError, SealError, User, VERSION, seal, truncate_on_char_boundary,
};
use crate::attestation::ES256;
use crate::crypto::{Crypto, KEY_LEN, NONCE_LEN};
use crate::keys::KeyRing;
use crate::soft::SoftCrypto;

/// Opens on a device that was never reset (reset ID 0), which opens every reset ID.
fn open(
    crypto: &SoftCrypto,
    keys: &KeyRing,
    rp_id: &str,
    id: &[u8],
) -> Result<Credential, OpenError> {
    super::open(crypto, keys, rp_id, id, 0)
}

/// A reset revokes what it leaves behind (CTAP 2.2 §6.6): an ID created under reset ID 2 opens
/// on a device at 2 and is refused under any other nonzero reset ID, whatever its key origin,
/// including one that a counter would have ranked lower (NVM wiped back to 0, then one reset);
/// a device whose NVM was wiped back to 0 opens it again.
#[test]
fn a_reset_revokes_older_ids() {
    let (mut crypto, keys) = platform();
    for credential in [
        Credential {
            reset_id: 2,
            ..seed_credential()
        },
        slot_credential(),
    ] {
        let id = seal(&mut crypto, &keys, RP, &credential).expect("fits");
        assert_eq!(
            super::open(&crypto, &keys, RP, &id, 2).as_ref(),
            Ok(&credential)
        );
        for other in [1, 3, u32::MAX] {
            assert_eq!(
                super::open(&crypto, &keys, RP, &id, other),
                Err(OpenError::Revoked),
                "reset ID {other}"
            );
        }
        assert_eq!(super::open(&crypto, &keys, RP, &id, 0), Ok(credential));
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// A fresh platform: node 11..11, random stream from seed 22..22, so the first nonce is the
/// first 12 bytes of SHA-256(seed || 0) as in derive.py.
fn platform() -> (SoftCrypto, KeyRing) {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let keys = KeyRing::new(&mut crypto);
    (crypto, keys)
}

fn seed_credential() -> Credential {
    Credential {
        key: KeySource::Seed([0x33; 32]),
        alg: ES256,
        cred_protect: CredProtect::Optional,
        user: None,
        reset_id: 0,
    }
}

fn slot_credential() -> Credential {
    Credential {
        key: KeySource::Slot {
            index: 5,
            tag: [0x44; 16],
        },
        alg: ES256,
        cred_protect: CredProtect::Required,
        user: Some(User {
            id: b"user-1".to_vec(),
            name: Some("alice".into()),
            display_name: Some("Alice A".into()),
        }),
        reset_id: 2,
    }
}

const RP: &str = "example.com";

/// A seed-recoverable, non-discoverable credential seals to the independently computed bytes
/// (derive.py: seed_credential_id) and opens back to itself.
#[test]
fn a_seed_credential_seals_to_the_reference_bytes() {
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &seed_credential()).expect("fits");
    assert_eq!(
        id,
        hex(
            "01f91b337d83bdbe27156e7edd0eea9cc1e290a0b84b42e803235727ea616f039eb36e1e625c5561234e7f720b366b1e3f7d49235a57c950bcca19b174af862a2ed1ebd9793d624598b419"
        )
    );
    assert_eq!(open(&crypto, &keys, RP, &id), Ok(seed_credential()));
}

/// A device-only, discoverable credential with names seals to the reference bytes (derive.py:
/// slot_credential_id) and opens back to itself.
#[test]
fn a_slot_credential_seals_to_the_reference_bytes() {
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &slot_credential()).expect("fits");
    assert_eq!(
        id,
        hex(
            "01f91b337d83bdbe27156e7edd02ea9dc1e297fd9d28359f745420509d161874e9c41969152b6051178844074d763d5f217f7375083da1342dcb7ec4c6ca6c2afe7683d2072253ee07eb6e27f1a6ea257e657060"
        )
    );
    assert_eq!(open(&crypto, &keys, RP, &id), Ok(slot_credential()));
}

/// A device-only, non-discoverable credential carries its credential seed for the derivation
/// under K_dev: it seals to the reference bytes (derive.py: device_credential_id), which differ
/// from the seed-recoverable one only in the origin, and opens back to itself.
#[test]
fn a_device_credential_seals_to_the_reference_bytes() {
    let (mut crypto, keys) = platform();
    let device = Credential {
        key: KeySource::Device([0x33; 32]),
        ..seed_credential()
    };
    let id = seal(&mut crypto, &keys, RP, &device).expect("fits");
    assert_eq!(
        id,
        hex(
            "01f91b337d83bdbe27156e7edd0eea9dc1e290a0b84b42e803235727ea616f039eb36e1e625c5561234e7f720b366b1e3f7d49235a57c950bcca19b75ca374959ffcaa13602260e20bc551"
        )
    );
    assert_eq!(open(&crypto, &keys, RP, &id), Ok(device));
    assert_eq!(
        format!("{:?}", KeySource::Device([0x33; 32])),
        "Device(<redacted>)"
    );
}

/// The RP ID hash is bound as AAD: an ID created for one RP does not open for another, so a
/// phishing site cannot replay it.
#[test]
fn an_id_does_not_open_for_another_rp() {
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &seed_credential()).expect("fits");
    assert_eq!(
        open(&crypto, &keys, "example.org", &id),
        Err(OpenError::Authentication)
    );
}

/// An ID sealed by another device (another node) does not open here.
#[test]
fn an_id_from_another_device_does_not_open() {
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &seed_credential()).expect("fits");
    let mut other = SoftCrypto::new([0x12; KEY_LEN], [0x22; KEY_LEN]);
    let other_keys = KeyRing::new(&mut other);
    assert_eq!(
        open(&other, &other_keys, RP, &id),
        Err(OpenError::Authentication)
    );
}

/// Every altered byte is refused: the version as an unknown version, any nonce, ciphertext or
/// tag byte by the tag check.
#[test]
fn every_tampered_byte_is_refused() {
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &slot_credential()).expect("fits");
    for at in 0..id.len() {
        let mut tampered = id.clone();
        tampered[at] ^= 0x01;
        let expected = if at == 0 {
            OpenError::Version
        } else {
            OpenError::Authentication
        };
        assert_eq!(
            open(&crypto, &keys, RP, &tampered),
            Err(expected),
            "byte {at}"
        );
    }
}

/// IDs shorter than version, nonce and tag, or longer than any sealed ID, are refused before
/// any decryption; an empty ciphertext is too short for a plaintext and fails the format.
#[test]
fn ids_of_impossible_lengths_are_refused() {
    let (crypto, keys) = platform();
    assert_eq!(open(&crypto, &keys, RP, &[]), Err(OpenError::Length));
    assert_eq!(
        open(&crypto, &keys, RP, &[VERSION; 28]),
        Err(OpenError::Length)
    );
    assert_eq!(
        open(
            &crypto,
            &keys,
            RP,
            &vec![VERSION; MAX_CREDENTIAL_ID_LEN + 1]
        ),
        Err(OpenError::Length)
    );
    // 29 bytes: version, nonce and tag with nothing between; the tag does not verify.
    assert_eq!(
        open(&crypto, &keys, RP, &[VERSION; 29]),
        Err(OpenError::Authentication)
    );
}

/// Seals arbitrary plaintext under the device's own wrapping key, as only a bug could.
fn seal_raw(crypto: &mut SoftCrypto, keys: &KeyRing, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    crypto.random(&mut nonce);
    let mut aad = vec![VERSION];
    aad.extend_from_slice(&crypto.sha256(&[RP.as_bytes()]));
    let mut data = plaintext.to_vec();
    let tag = crypto.aes256_gcm_seal(&keys.wrap_key(crypto), &nonce, &aad, &mut data);
    let mut id = vec![VERSION];
    id.extend_from_slice(&nonce);
    id.extend_from_slice(&data);
    id.extend_from_slice(&tag);
    id
}

/// An authenticated plaintext that is not this format is refused, never half-read: a missing
/// epoch, an unknown key, a seed of the wrong length, a device-only origin carrying a seed, a
/// discoverable credential without a user ID, trailing bytes.
#[test]
fn authenticated_plaintexts_of_another_shape_are_refused() {
    let cs = [0x58, 0x20]
        .iter()
        .copied()
        .chain([0x33; 32])
        .collect::<Vec<_>>();
    // `head`, then the 32-byte seed with its byte-string header, then `tail`.
    let around_seed = |head: &[u8], tail: &[u8]| [head, &cs, tail].concat();
    let cases = [
        // No epoch: {1: 1, 2: -7, 3: cs, 6: 1, 7: false}.
        around_seed(
            &[0xA5, 0x01, 0x01, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF4],
        ),
        // An extra key 12 after the epoch.
        around_seed(
            &[0xA7, 0x01, 0x01, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00, 0x0C, 0x00],
        ),
        // A 31-byte seed.
        [
            &[0xA6, 0x01, 0x01, 0x02, 0x26, 0x03, 0x58, 0x1F][..],
            &[0x33; 31],
            &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00],
        ]
        .concat(),
        // An origin other than 0 and 1.
        around_seed(
            &[0xA6, 0x01, 0x02, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00],
        ),
        // A device-only seed under K_dev on a discoverable credential: {1: 0, 2: -7, 3: cs, 6: 1,
        // 7: true, 8: h'01', 11: 0}.
        around_seed(
            &[0xA7, 0x01, 0x00, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF5, 0x08, 0x41, 0x01, 0x0B, 0x00],
        ),
        // A slot key on a non-discoverable credential: {1: 0, 2: -7, 4: 5, 5: tag, 6: 1, 7: false,
        // 11: 0}.
        [
            &[0xA7, 0x01, 0x00, 0x02, 0x26, 0x04, 0x05, 0x05, 0x50][..],
            &[0x44; 16],
            &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00],
        ]
        .concat(),
        // rk true without key 8.
        around_seed(
            &[0xA6, 0x01, 0x01, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF5, 0x0B, 0x00],
        ),
        // A credProtect level outside 1..=3.
        around_seed(
            &[0xA6, 0x01, 0x01, 0x02, 0x26, 0x03],
            &[0x06, 0x04, 0x07, 0xF4, 0x0B, 0x00],
        ),
        // A valid map followed by a trailing byte.
        around_seed(
            &[0xA6, 0x01, 0x01, 0x02, 0x26, 0x03],
            &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00, 0x00],
        ),
    ];
    let (mut crypto, keys) = platform();
    for (index, plaintext) in cases.iter().enumerate() {
        let id = seal_raw(&mut crypto, &keys, plaintext);
        assert_eq!(
            open(&crypto, &keys, RP, &id),
            Err(OpenError::Plaintext),
            "case {index}"
        );
    }
    // The control: the same helper with the well-formed plaintext opens.
    let valid = around_seed(
        &[0xA6, 0x01, 0x01, 0x02, 0x26, 0x03],
        &[0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00],
    );
    let id = seal_raw(&mut crypto, &keys, &valid);
    assert_eq!(open(&crypto, &keys, RP, &id), Ok(seed_credential()));
}

/// Names longer than 64 bytes are cut on a character boundary, never inside a UTF-8 sequence.
#[test]
fn long_names_are_cut_on_a_character_boundary() {
    // 63 ASCII bytes then a 2-byte "é": 64 bytes would split it, so 63 are kept.
    let name = format!("{}é", "a".repeat(63));
    assert_eq!(truncate_on_char_boundary(&name, MAX_NAME_LEN).len(), 63);
    assert_eq!(truncate_on_char_boundary("short", MAX_NAME_LEN), "short");
    let mut credential = slot_credential();
    credential.user.as_mut().expect("user").display_name = Some(name);
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &credential).expect("fits");
    let opened = open(&crypto, &keys, RP, &id).expect("opens");
    assert_eq!(
        opened.user.expect("user").display_name.as_deref(),
        Some("a".repeat(63).as_str())
    );
}

/// A user ID must be 1..=64 bytes (WebAuthn L3 §5.1.3 step 5).
#[test]
fn user_ids_outside_one_to_64_bytes_are_refused() {
    let (mut crypto, keys) = platform();
    for length in [0, MAX_USER_ID_LEN + 1] {
        let mut credential = slot_credential();
        credential.user.as_mut().expect("user").id = vec![0x55; length];
        assert_eq!(
            seal(&mut crypto, &keys, RP, &credential),
            Err(SealError::TooLong),
            "{length}"
        );
    }
}

/// A slot key belongs to a discoverable credential, whose entry can delete it, and a key under
/// K_dev to a non-discoverable one: the other pairings are refused when sealing.
#[test]
fn a_key_source_must_fit_the_discoverability() {
    let (mut crypto, keys) = platform();
    let discoverable_device = Credential {
        key: KeySource::Device([0x33; 32]),
        ..slot_credential()
    };
    let non_discoverable_slot = Credential {
        user: None,
        ..slot_credential()
    };
    for credential in [discoverable_device, non_discoverable_slot] {
        assert_eq!(
            seal(&mut crypto, &keys, RP, &credential),
            Err(SealError::KeySource),
            "{credential:?}"
        );
    }
}

/// The credential seed is key material: Debug output, of the key source and of a whole
/// credential, never prints it, so a log line cannot leak a private key.
#[test]
fn debug_output_redacts_the_credential_seed() {
    assert_eq!(
        format!("{:?}", KeySource::Seed([0x33; 32])),
        "Seed(<redacted>)"
    );
    let credential = format!("{:?}", seed_credential());
    assert!(credential.contains("Seed(<redacted>)"), "{credential}");
    assert!(!credential.contains("51"), "{credential}");
}

/// The largest credential (all fields at their maximum) fits MAX_CREDENTIAL_ID_LEN and opens.
#[test]
fn the_largest_credential_fits_the_reported_maximum() {
    let credential = Credential {
        key: KeySource::Slot {
            index: u16::MAX,
            tag: [0xFF; 16],
        },
        alg: i64::MIN,
        cred_protect: CredProtect::Required,
        user: Some(User {
            id: vec![0xFF; MAX_USER_ID_LEN],
            name: Some("n".repeat(MAX_NAME_LEN)),
            display_name: Some("d".repeat(MAX_NAME_LEN)),
        }),
        reset_id: u32::MAX,
    };
    let (mut crypto, keys) = platform();
    let id = seal(&mut crypto, &keys, RP, &credential).expect("fits");
    assert!(id.len() <= MAX_CREDENTIAL_ID_LEN, "{} bytes", id.len());
    assert_eq!(open(&crypto, &keys, RP, &id), Ok(credential));
}

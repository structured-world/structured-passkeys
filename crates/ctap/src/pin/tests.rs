//! PIN/UV auth protocols one and two (CTAP 2.2 §6.5.6, §6.5.7) and the pinUvAuthToken state
//! (§6.5.2.1, §6.5.3.2). The platform side is computed here with the RustCrypto crates directly,
//! not with the code under test.

use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

use super::{
    ClientPin, Features, INITIAL_USAGE_TIME_LIMIT_MS, MAX_USAGE_TIME_PERIOD_MS, Method,
    PADDED_PIN_LEN, Permissions, Protocol, SharedSecret, USER_PRESENT_TIME_LIMIT_MS, new_pin,
};
use crate::crypto::{Crypto, KEY_LEN};
use crate::soft::SoftCrypto;

fn crypto() -> SoftCrypto {
    SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN])
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA-256 with a salt of 32 zero bytes and a 32-byte output (§6.5.7 `kdf`).
fn hkdf(z: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), z)
        .expand(info, &mut out)
        .expect("32 bytes is a valid length");
    out
}

/// Protocol one's shared secret is SHA-256(Z) for both MAC and encryption (§6.5.6 `kdf`):
/// `verify` takes the first 16 bytes of HMAC-SHA-256 under it and nothing else.
#[test]
fn protocol_one_macs_with_sha256_of_z() {
    let z = [0x5A; KEY_LEN];
    let secret = SharedSecret::new(&crypto(), Protocol::One, &z);
    let key = Sha256::digest(z);
    let message = b"message";
    let mac = hmac(&key, message);
    assert!(secret.verify(&crypto(), &[message], &mac[..16]));
    // The whole HMAC is not protocol one's signature, nor is a wrong one.
    assert!(!secret.verify(&crypto(), &[message], &mac));
    let mut wrong = mac;
    wrong[0] ^= 1;
    assert!(!secret.verify(&crypto(), &[message], &wrong[..16]));
}

/// Protocol two derives its HMAC key with HKDF info "CTAP2 HMAC key" and verifies the whole
/// 32-byte HMAC; a message split into parts is their concatenation (§6.5.7).
#[test]
fn protocol_two_macs_with_the_hkdf_hmac_key() {
    let z = [0xA5; KEY_LEN];
    let secret = SharedSecret::new(&crypto(), Protocol::Two, &z);
    let mac = hmac(&hkdf(&z, b"CTAP2 HMAC key"), b"newPinEncpinHashEnc");
    assert!(secret.verify(&crypto(), &[b"newPinEnc", b"pinHashEnc"], &mac));
    assert!(!secret.verify(&crypto(), &[b"newPinEnc", b"pinHashEnc"], &mac[..16]));
    // Keyed with the AES key instead, the MAC does not verify: the two keys differ.
    let wrong = hmac(&hkdf(&z, b"CTAP2 AES key"), b"newPinEncpinHashEnc");
    assert!(!secret.verify(&crypto(), &[b"newPinEnc", b"pinHashEnc"], &wrong));
}

/// AES-256-CBC as the platform computes it, to check `encrypt` and `decrypt` against.
fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
    let cipher = aes::Aes256::new(key.into());
    let mut previous = *iv;
    let mut out = Vec::new();
    for chunk in plaintext.chunks(16) {
        let mut block = aes::Block::default();
        for ((byte, &plain), &chain) in block.iter_mut().zip(chunk).zip(&previous) {
            *byte = plain ^ chain;
        }
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        previous.copy_from_slice(&block);
    }
    out
}

/// Protocol one encrypts with an all-zero IV and no IV in the output; protocol two prepends a
/// random IV and keys AES with the HKDF "CTAP2 AES key" (§6.5.6, §6.5.7).
#[test]
fn encrypt_and_decrypt_follow_each_protocol() {
    let z = [0x3C; KEY_LEN];
    let plaintext = [0x42u8; 32];
    let mut out = [0u8; 80];

    let one = SharedSecret::new(&crypto(), Protocol::One, &z);
    let length = one
        .encrypt(&mut crypto(), &plaintext, &mut out)
        .expect("two blocks");
    let key_one: [u8; 32] = Sha256::digest(z).into();
    assert_eq!(out[..length], cbc_encrypt(&key_one, &[0; 16], &plaintext));
    let mut decrypted = [0u8; 80];
    assert_eq!(
        one.decrypt(&crypto(), &out[..length], &mut decrypted),
        Ok(32)
    );
    assert_eq!(decrypted[..32], plaintext);

    let two = SharedSecret::new(&crypto(), Protocol::Two, &z);
    let length = two
        .encrypt(&mut crypto(), &plaintext, &mut out)
        .expect("two blocks");
    assert_eq!(length, 48, "IV and two blocks");
    let iv: [u8; 16] = out[..16].try_into().expect("16 bytes");
    let key_two = hkdf(&z, b"CTAP2 AES key");
    assert_eq!(out[16..length], cbc_encrypt(&key_two, &iv, &plaintext));
    assert_eq!(
        two.decrypt(&crypto(), &out[..length], &mut decrypted),
        Ok(32)
    );
    assert_eq!(decrypted[..32], plaintext);
}

/// Decrypt refuses what is not a whole number of blocks, and a protocol two ciphertext shorter
/// than its IV (§6.5.6, §6.5.7 `decrypt`).
#[test]
fn decrypt_refuses_partial_blocks() {
    let z = [0x01; KEY_LEN];
    let mut out = [0u8; 80];
    let one = SharedSecret::new(&crypto(), Protocol::One, &z);
    assert!(one.decrypt(&crypto(), &[0u8; 15], &mut out).is_err());
    let two = SharedSecret::new(&crypto(), Protocol::Two, &z);
    assert!(two.decrypt(&crypto(), &[0u8; 15], &mut out).is_err());
    assert!(two.decrypt(&crypto(), &[0u8; 33], &mut out).is_err());
    // An IV alone decrypts to nothing.
    assert_eq!(two.decrypt(&crypto(), &[0u8; 16], &mut out), Ok(0));
}

/// The key agreement key is a P-256 key whose public point the platform's ECDH reaches: both
/// sides compute the same Z, so both derive the same shared secret.
#[test]
fn both_sides_agree_on_the_shared_secret() {
    let mut device = crypto();
    let client_pin = ClientPin::new(&mut device);
    let platform = p256::SecretKey::from_slice(&[0x77; 32]).expect("a valid scalar");
    let platform_point = platform.public_key().to_sec1_point(false);
    let peer: [u8; 65] = platform_point.as_bytes().try_into().expect("uncompressed");
    let device_public =
        p256::PublicKey::from_sec1_bytes(client_pin.public_key(Protocol::Two)).expect("on curve");
    let z = p256::ecdh::diffie_hellman(platform.to_nonzero_scalar(), device_public.as_affine());
    let secret = client_pin
        .shared_secret(&device, Protocol::Two, &peer)
        .expect("a valid peer");
    let mac = hmac(&hkdf(z.raw_secret_bytes(), b"CTAP2 HMAC key"), b"m");
    assert!(secret.verify(&device, &[b"m"], &mac));
}

/// A peer key off the curve is refused, which getKeyAgreement's callers answer with
/// CTAP1_ERR_INVALID_PARAMETER.
#[test]
fn a_peer_off_the_curve_is_refused() {
    let mut device = crypto();
    let client_pin = ClientPin::new(&mut device);
    let mut off_curve = [0u8; 65];
    off_curve[0] = 0x04;
    off_curve[1] = 1;
    assert!(
        client_pin
            .shared_secret(&device, Protocol::One, &off_curve)
            .is_err()
    );
}

/// Each protocol has its own key agreement key, and `regenerate` replaces only that one.
#[test]
fn regenerate_replaces_one_protocols_key() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    let one = *client_pin.public_key(Protocol::One);
    let two = *client_pin.public_key(Protocol::Two);
    assert_ne!(one, two);
    client_pin.regenerate(&mut device, Protocol::One);
    assert_ne!(*client_pin.public_key(Protocol::One), one);
    assert_eq!(*client_pin.public_key(Protocol::Two), two);
}

/// `resetPinUvAuthToken` gives every protocol a fresh token and stops the one in use, so a token
/// issued before no longer verifies.
#[test]
fn reset_tokens_invalidates_issued_tokens() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    client_pin.begin_using(0, false, Permissions::DEFAULT, None);
    let old = *client_pin.token(Protocol::Two);
    let mac = hmac(&old, b"m");
    assert!(client_pin.verify_token(&device, Protocol::Two, &[b"m"], &mac, 1));
    client_pin.reset_tokens(&mut device);
    assert_ne!(*client_pin.token(Protocol::Two), old);
    client_pin.begin_using(2, false, Permissions::DEFAULT, None);
    assert!(!client_pin.verify_token(&device, Protocol::Two, &[b"m"], &mac, 3));
}

/// A token that is not in use never verifies, whatever its value (§6.5.6 `verify` step 1).
#[test]
fn a_token_not_in_use_does_not_verify() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    let mac = hmac(client_pin.token(Protocol::One), b"m");
    assert!(!client_pin.verify_token(&device, Protocol::One, &[b"m"], &mac[..16], 0));
}

/// The usage timer (§6.5.3.2): a token not used within the initial usage time limit stops; a
/// used one lasts the max usage time period; cached user presence ends after its limit.
#[test]
fn the_usage_timer_stops_the_token() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    let start = 1_000;

    client_pin.begin_using(start, true, Permissions::DEFAULT, None);
    assert!(client_pin.in_use(start + INITIAL_USAGE_TIME_LIMIT_MS - 1));
    assert!(!client_pin.in_use(start + INITIAL_USAGE_TIME_LIMIT_MS));

    client_pin.begin_using(start, true, Permissions::DEFAULT, None);
    let mac = hmac(client_pin.token(Protocol::Two), b"m");
    assert!(client_pin.user_present(start + 1));
    assert!(client_pin.verify_token(&device, Protocol::Two, &[b"m"], &mac, start + 1));
    assert!(client_pin.in_use(start + INITIAL_USAGE_TIME_LIMIT_MS));
    assert!(!client_pin.user_present(start + USER_PRESENT_TIME_LIMIT_MS));
    assert!(client_pin.user_verified(start + MAX_USAGE_TIME_PERIOD_MS - 1));
    assert!(!client_pin.in_use(start + MAX_USAGE_TIME_PERIOD_MS));
    assert!(!client_pin.user_verified(start + MAX_USAGE_TIME_PERIOD_MS));
}

/// Permissions and the permissions RP ID: a token without an RP ID permits any and is bound by
/// its first use; a bound token permits only its RP; an operation that tested user presence
/// leaves only `lbw` (§6.5.5.7).
#[test]
fn permissions_and_rp_id_binding() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    let example = device.sha256(&[b"example.com"]);
    let other = device.sha256(&[b"other.example"]);

    client_pin.begin_using(0, false, Permissions::DEFAULT, None);
    assert!(client_pin.has_permission(Permissions::MAKE_CREDENTIAL));
    assert!(client_pin.has_permission(Permissions::GET_ASSERTION));
    assert!(!client_pin.has_permission(Permissions::CREDENTIAL_MANAGEMENT));
    assert!(client_pin.permits_rp_id(&other));
    assert!(client_pin.bind_rp_id(&example));
    assert!(client_pin.permits_rp_id(&example));
    assert!(!client_pin.permits_rp_id(&other));
    assert!(!client_pin.bind_rp_id(&other));

    client_pin.begin_using(0, false, Permissions::from_request(0x13), Some(example));
    assert!(!client_pin.permits_rp_id(&other));
    client_pin.clear_permissions_except_lbw();
    assert!(!client_pin.has_permission(Permissions::MAKE_CREDENTIAL));
    assert!(client_pin.has_permission(Permissions::LARGE_BLOB_WRITE));

    client_pin.stop_using();
    assert!(!client_pin.has_permission(Permissions::LARGE_BLOB_WRITE));
}

/// Undefined permission bits are ignored (§6.5.5.7.2 step 4).
#[test]
fn undefined_permission_bits_are_ignored() {
    assert_eq!(Permissions::from_request(0x83).bits(), 0x03);
    assert!(Permissions::from_request(0x80).is_empty());
}

/// §6.5.5.7.2 and §6.5.5.7.3 step 4: a permission for a feature the authenticator does not
/// report is unauthorized; `mc` and `ga` always are authorized, `be` never here; `pcmr` only
/// alone; `acfg` follows `authnrCfg` for the client PIN and `uvAcfg` for built-in UV.
#[test]
fn unauthorized_permissions_follow_the_features() {
    let none = Features {
        cred_mgmt: false,
        authnr_cfg: false,
        uv_acfg: false,
        large_blobs: false,
        per_cred_mgmt_ro: false,
    };
    let all = Features {
        cred_mgmt: true,
        authnr_cfg: true,
        uv_acfg: true,
        large_blobs: true,
        per_cred_mgmt_ro: true,
    };
    for method in [Method::ClientPin, Method::BuiltInUv] {
        assert!(!none.unauthorized(Permissions::DEFAULT, method));
        for bit in [0x04, 0x08, 0x10, 0x20, 0x40] {
            assert!(
                none.unauthorized(Permissions::from_request(bit), method),
                "{bit:#x}"
            );
        }
        assert!(!all.unauthorized(Permissions::from_request(0x37), method));
        assert!(all.unauthorized(Permissions::from_request(0x08), method));
        assert!(!all.unauthorized(Permissions::from_request(0x40), method));
        assert!(all.unauthorized(Permissions::from_request(0x41), method));
    }
    let pin_config_only = Features {
        authnr_cfg: true,
        ..none
    };
    assert!(!pin_config_only.unauthorized(Permissions::AUTHENTICATOR_CONFIG, Method::ClientPin));
    assert!(pin_config_only.unauthorized(Permissions::AUTHENTICATOR_CONFIG, Method::BuiltInUv));
}

/// Three consecutive mismatches require a power cycle; a match in between starts the count
/// over (§6.5.5.6 step 5.7.1.2.2).
#[test]
fn three_consecutive_mismatches_require_a_power_cycle() {
    let mut device = crypto();
    let mut client_pin = ClientPin::new(&mut device);
    assert!(!client_pin.mismatch());
    assert!(!client_pin.mismatch());
    client_pin.pin_matched();
    assert!(!client_pin.mismatch());
    assert!(!client_pin.mismatch());
    assert!(!client_pin.power_cycle_required());
    assert!(client_pin.mismatch());
    assert!(client_pin.power_cycle_required());
}

fn padded(pin: &[u8]) -> [u8; PADDED_PIN_LEN] {
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..pin.len()].copy_from_slice(pin);
    padded
}

/// The PIN policy (§6.5.1, §6.5.5.5 steps 5.8 to 5.10): trailing zeros dropped, at least four
/// code points, at most 63 bytes, UTF-8.
#[test]
fn the_pin_policy_counts_code_points() {
    assert_eq!(new_pin(&padded(b"1234")), Some(&b"1234"[..]));
    assert_eq!(new_pin(&padded(b"123")), None);
    // Four code points of two bytes each pass; two of them do not, though they are four bytes.
    assert!(new_pin(&padded("ąčęė".as_bytes())).is_some());
    assert_eq!(new_pin(&padded("ąč".as_bytes())), None);
    assert!(new_pin(&padded(&[b'7'; 63])).is_some());
    assert_eq!(
        new_pin(&[b'7'; PADDED_PIN_LEN]),
        None,
        "64 bytes leave no padding"
    );
    assert_eq!(
        new_pin(&padded(&[0xFF, 0xFE, 0xFD, 0xFC])),
        None,
        "not UTF-8"
    );
    assert_eq!(new_pin(&padded(b"")), None);
}

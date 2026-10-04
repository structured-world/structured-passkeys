//! The key hierarchy against values computed independently by `tests/vectors/derive.py` (Python
//! `cryptography` and `hmac`), never by this crate.

use zeroize::Zeroizing;

use super::{APPLICATION_PATH, DeviceKeys, KeyRing};
use crate::crypto::{Crypto, CryptoError, KEY_LEN, NONCE_LEN, PUBLIC_KEY_LEN, Signature, TAG_LEN};
use crate::soft::SoftCrypto;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn crypto() -> SoftCrypto {
    SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN])
}

/// K_wrap from the node 11..11 through K_root (derive.py: k_wrap). A wrong salt, label or
/// chaining order changes it.
#[test]
fn wrap_key_follows_the_hierarchy() {
    let mut crypto = crypto();
    let keys = KeyRing::new(&mut crypto);
    assert_eq!(
        keys.wrap_key(&crypto)[..],
        hex("b065e5c54236dc5ebdd476cb647ea43ed7b498a01222b140f0fa713ac124f341")[..]
    );
}

/// The seed-recoverable key for cs 33..33 and its public key (derive.py: credential_key,
/// credential_public_key); counter 0 is already in range for this seed.
#[test]
fn credential_key_follows_the_hierarchy() {
    let mut crypto = crypto();
    let keys = KeyRing::new(&mut crypto);
    let private_key = keys
        .credential_key(&crypto, &[0x33; KEY_LEN])
        .expect("in range");
    assert_eq!(
        private_key[..],
        hex("1c25ee63dee5fe30ce9c52ab615f52ac394a85337799970d800c083971cfb721")[..]
    );
    let public_key = crypto.p256_public_key(&private_key).expect("valid key");
    assert_eq!(
        public_key[..],
        hex(
            "045d31fcf65ebd9f1f252c1d9fd97dd225f3bf7dde1c4967b09457ca4156889a0407903bd11c6253ad24a56919c313027951af0759d9ce749aa8bbcf62290f718b"
        )[..]
    );
}

/// A non-discoverable device-only key for cs 33..33 under the device key 55..55 (derive.py:
/// device_credential_key): the seed-recoverable derivation with K_dev in place of K_root, so it
/// differs from the seed-recoverable key of the same cs.
#[test]
fn device_credential_key_derives_under_the_device_key() {
    let crypto = crypto();
    let keys = DeviceKeys::new(Zeroizing::new([0x55; KEY_LEN]));
    let private_key = keys
        .credential_key(&crypto, &[0x33; KEY_LEN])
        .expect("in range");
    assert_eq!(
        private_key[..],
        hex("4aedc94cefdba1c9fffc78ede132f84e44e50e437210f44369a362a22849210d")[..]
    );
    assert_eq!(format!("{keys:?}"), "DeviceKeys");
}

/// The software platform with the HKDF block for counter 0 replaced by 2^256 - 1, outside P-256's
/// range, so the derivation must reject it and move to counter 1.
struct RejectFirstCounter(SoftCrypto);

impl Crypto for RejectFirstCounter {
    fn random(&mut self, out: &mut [u8]) {
        self.0.random(out);
    }
    fn sha256_into(&self, parts: &[&[u8]], out: &mut [u8; KEY_LEN]) {
        self.0.sha256_into(parts, out);
    }
    fn hmac_sha256(&self, key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_LEN]> {
        if parts == [&b"es256"[..], &[0u8][..], &[1u8][..]] {
            return Zeroizing::new([0xFF; KEY_LEN]);
        }
        self.0.hmac_sha256(key, parts)
    }
    fn aes256_gcm_seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; TAG_LEN] {
        self.0.aes256_gcm_seal(key, nonce, aad, data)
    }
    fn aes256_gcm_open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        self.0.aes256_gcm_open(key, nonce, aad, data, tag)
    }
    fn aes256_cbc_encrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.aes256_cbc_encrypt(key, iv, data)
    }
    fn aes256_cbc_decrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.aes256_cbc_decrypt(key, iv, data)
    }
    fn p256_ecdh(
        &self,
        private_key: &[u8; KEY_LEN],
        peer: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        self.0.p256_ecdh(private_key, peer)
    }
    fn p256_public_key(
        &self,
        private_key: &[u8; KEY_LEN],
    ) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        self.0.p256_public_key(private_key)
    }
    fn p256_sign(
        &mut self,
        private_key: &[u8; KEY_LEN],
        digest: &[u8; KEY_LEN],
    ) -> Result<Signature, CryptoError> {
        self.0.p256_sign(private_key, digest)
    }
    fn application_node(&mut self) -> Zeroizing<[u8; KEY_LEN]> {
        self.0.application_node()
    }
}

/// A candidate outside 0 < d < n is rejected and the next counter used (derive.py:
/// credential_key_counter_1); reducing it modulo n instead would give a biased key and fail here.
#[test]
fn an_out_of_range_candidate_moves_to_the_next_counter() {
    let mut crypto = RejectFirstCounter(crypto());
    let keys = KeyRing::new(&mut crypto);
    let private_key = keys
        .credential_key(&crypto, &[0x33; KEY_LEN])
        .expect("in range");
    assert_eq!(
        private_key[..],
        hex("f05ca124212de32e6ae315de43e9472afc25f71a7c7a720f02b907a853919ea3")[..]
    );
}

/// The application path is m/5722689'/5262163'/21328'/0', all hardened.
#[test]
fn application_path_is_the_declared_one() {
    assert_eq!(
        APPLICATION_PATH,
        [0x8057_5241, 0x8050_4B53, 0x8000_5350, 0x8000_0000]
    );
}

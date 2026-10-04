//! The device's [`Crypto`]: the cx library of the Ledger OS through the SDK. Every cx context and
//! key structure is wiped after use, since it holds key material or state derived from it.

use core::mem::size_of;

use ledger_device_sdk::ecc::{CurvesId, Secp256r1, bip32_derive};
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::hmac::HMACInit;
use ledger_device_sdk::hmac::sha2::Sha2_256 as HmacSha256;
use ledger_device_sdk::random::rand_bytes;
use ledger_device_sdk::sys::{
    CX_DECRYPT, CX_ENCRYPT, CX_OK, cx_aes_dec_block, cx_aes_enc_block, cx_aes_gcm_check_tag,
    cx_aes_gcm_context_t, cx_aes_gcm_finish, cx_aes_gcm_init, cx_aes_gcm_set_key, cx_aes_gcm_start,
    cx_aes_gcm_update, cx_aes_gcm_update_aad, cx_aes_init_key_no_throw, cx_aes_key_t,
};
use structured_passkeys_ctap::crypto::{
    AES_BLOCK_LEN, Crypto, CryptoError, KEY_LEN, NONCE_LEN, PUBLIC_KEY_LEN, Signature, TAG_LEN,
    is_p256_private_key,
};
use structured_passkeys_ctap::keys::APPLICATION_PATH;
use zeroize::{Zeroize, Zeroizing};

/// Zeroes the bytes of `value`, a cx context or key structure.
fn wipe<T>(value: &mut T) {
    // SAFETY: the cx structures are plain C data: every byte pattern, zeros included, is a value
    // of them, and nothing reads them after the wipe but their drop, which they do not have.
    let bytes =
        unsafe { core::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) };
    bytes.zeroize();
}

/// A zeroed cx structure, filled by its init function.
fn zeroed<T>() -> T {
    // SAFETY: as in `wipe`, zeros are a value of the plain C structures this is used for.
    unsafe { core::mem::zeroed() }
}

/// The device's cryptography.
pub struct DeviceCrypto;

impl DeviceCrypto {
    /// The AES-256 key schedule of `key`; the caller wipes it.
    fn aes_key(key: &[u8; KEY_LEN]) -> cx_aes_key_t {
        let mut schedule: cx_aes_key_t = zeroed();
        // SAFETY: a 32-byte key and a key structure to fill.
        let status = unsafe { cx_aes_init_key_no_throw(key.as_ptr(), KEY_LEN, &mut schedule) };
        assert_eq!(status, CX_OK, "a 32-byte AES key is valid");
        schedule
    }

    /// Runs AES-GCM over `data` in place, a block at a time through a buffer, so the cx call
    /// never reads and writes the same bytes.
    fn gcm_update(context: &mut cx_aes_gcm_context_t, data: &mut [u8]) {
        let mut out = [0u8; AES_BLOCK_LEN];
        for chunk in data.chunks_mut(AES_BLOCK_LEN) {
            // SAFETY: `chunk` and `out` hold at least `chunk.len()` bytes and do not overlap.
            let status = unsafe {
                cx_aes_gcm_update(context, chunk.as_ptr(), out.as_mut_ptr(), chunk.len())
            };
            assert_eq!(status, CX_OK, "a started AES-GCM context takes data");
            chunk.copy_from_slice(&out[..chunk.len()]);
        }
        out.zeroize();
    }

    /// A context started for `mode` with `key`, `nonce` and `aad`.
    fn gcm_start(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        mode: u32,
    ) -> cx_aes_gcm_context_t {
        let mut context: cx_aes_gcm_context_t = zeroed();
        // SAFETY: the context is ours; the key, nonce and AAD are read for their lengths.
        unsafe {
            cx_aes_gcm_init(&mut context);
            assert_eq!(
                cx_aes_gcm_set_key(&mut context, key.as_ptr(), KEY_LEN),
                CX_OK,
                "a 32-byte AES key is valid"
            );
            assert_eq!(
                cx_aes_gcm_start(&mut context, mode, nonce.as_ptr(), NONCE_LEN),
                CX_OK,
                "a 96-bit nonce is valid"
            );
            assert_eq!(
                cx_aes_gcm_update_aad(&mut context, aad.as_ptr(), aad.len()),
                CX_OK,
                "AAD goes in before the data"
            );
        }
        context
    }
}

impl Crypto for DeviceCrypto {
    fn random(&mut self, out: &mut [u8]) {
        rand_bytes(out);
    }

    fn sha256_into(&self, parts: &[&[u8]], out: &mut [u8; KEY_LEN]) {
        let mut hash = Sha2_256::new();
        for part in parts {
            hash.update(part).expect("SHA-256 takes any input");
        }
        hash.finalize(out).expect("the digest fits 32 bytes");
        // The state may have hashed secrets (a PIN, an ECDH output).
        wipe(&mut hash);
    }

    fn hmac_sha256(&self, key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_LEN]> {
        let mut mac = HmacSha256::new(key);
        for part in parts {
            mac.update(part).expect("HMAC takes any input");
        }
        let mut tag = Zeroizing::new([0u8; KEY_LEN]);
        mac.finalize(&mut tag[..]).expect("the tag fits 32 bytes");
        wipe(&mut mac);
        tag
    }

    fn aes256_gcm_seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; TAG_LEN] {
        let mut context = Self::gcm_start(key, nonce, aad, CX_ENCRYPT);
        Self::gcm_update(&mut context, data);
        let mut tag = [0u8; TAG_LEN];
        // SAFETY: the context was started above; the tag buffer holds TAG_LEN bytes.
        let status = unsafe { cx_aes_gcm_finish(&mut context, tag.as_mut_ptr(), TAG_LEN) };
        assert_eq!(status, CX_OK, "a started AES-GCM context finishes");
        wipe(&mut context);
        tag
    }

    fn aes256_gcm_open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        let mut context = Self::gcm_start(key, nonce, aad, CX_DECRYPT);
        Self::gcm_update(&mut context, data);
        // SAFETY: the context was started above; the tag holds TAG_LEN bytes.
        let status = unsafe { cx_aes_gcm_check_tag(&mut context, tag.as_ptr(), TAG_LEN) };
        wipe(&mut context);
        if status == CX_OK {
            Ok(())
        } else {
            Err(CryptoError::Authentication)
        }
    }

    fn aes256_cbc_encrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; AES_BLOCK_LEN],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        if !data.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(CryptoError::Length);
        }
        let mut schedule = Self::aes_key(key);
        let mut chain = *iv;
        for chunk in data.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            // C_i = E(P_i xor C_{i-1}), C_0 = IV (SP 800-38A §6.2).
            for (byte, &previous) in chunk.iter_mut().zip(&chain) {
                *byte ^= previous;
            }
            // SAFETY: both blocks hold 16 bytes; the input is copied out first, so they differ.
            let status = unsafe { cx_aes_enc_block(&schedule, chunk.as_ptr(), chain.as_mut_ptr()) };
            assert_eq!(status, CX_OK, "a block encrypts");
            chunk.copy_from_slice(&chain);
        }
        wipe(&mut schedule);
        Ok(())
    }

    fn aes256_cbc_decrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; AES_BLOCK_LEN],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        if !data.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(CryptoError::Length);
        }
        let mut schedule = Self::aes_key(key);
        let mut chain = *iv;
        let mut plain = [0u8; AES_BLOCK_LEN];
        // One copy of the block being decrypted, reused and wiped: the ciphertext can be a PIN
        // hash, which with the key agreement key would let stale stack bytes be tested offline.
        let mut ciphertext = [0u8; AES_BLOCK_LEN];
        for chunk in data.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            // P_i = D(C_i) xor C_{i-1}, C_0 = IV (SP 800-38A §6.2).
            // SAFETY: both blocks hold 16 bytes and do not overlap.
            let status = unsafe { cx_aes_dec_block(&schedule, chunk.as_ptr(), plain.as_mut_ptr()) };
            assert_eq!(status, CX_OK, "a block decrypts");
            ciphertext.copy_from_slice(chunk);
            for ((byte, &decrypted), &previous) in chunk.iter_mut().zip(&plain).zip(&chain) {
                *byte = decrypted ^ previous;
            }
            chain.copy_from_slice(&ciphertext);
        }
        plain.zeroize();
        ciphertext.zeroize();
        chain.zeroize();
        wipe(&mut schedule);
        Ok(())
    }

    fn p256_ecdh(
        &self,
        private_key: &[u8; KEY_LEN],
        peer: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        if !is_p256_private_key(private_key) {
            return Err(CryptoError::InvalidKey);
        }
        // The key structure wipes its key on drop.
        let key = Secp256r1::from(private_key);
        let mut z = key.ecdh(peer).map_err(|_| CryptoError::InvalidPoint)?;
        let shared = Zeroizing::new(z);
        z.zeroize();
        Ok(shared)
    }

    fn p256_public_key(
        &self,
        private_key: &[u8; KEY_LEN],
    ) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        if !is_p256_private_key(private_key) {
            return Err(CryptoError::InvalidKey);
        }
        let key = Secp256r1::from(private_key);
        let public = key.public_key().map_err(|_| CryptoError::InvalidKey)?;
        Ok(public.pubkey)
    }

    fn p256_sign(
        &mut self,
        private_key: &[u8; KEY_LEN],
        digest: &[u8; KEY_LEN],
    ) -> Result<Signature, CryptoError> {
        if !is_p256_private_key(private_key) {
            return Err(CryptoError::InvalidKey);
        }
        let key = Secp256r1::from(private_key);
        // ECDSA with a nonce from the TRNG; the cx library writes DER.
        let (der, length, _parity) = key.sign(digest).map_err(|_| CryptoError::InvalidKey)?;
        let length = usize::try_from(length).map_err(|_| CryptoError::InvalidKey)?;
        Signature::from_der(der.get(..length).ok_or(CryptoError::InvalidKey)?)
            .ok_or(CryptoError::InvalidKey)
    }

    fn application_node(&mut self) -> Zeroizing<[u8; KEY_LEN]> {
        // The OS writes the private key, then the next 32 bytes.
        let mut node = Zeroizing::new([0u8; 64]);
        bip32_derive(CurvesId::Secp256r1, &APPLICATION_PATH, &mut node[..], None)
            .expect("the application path is declared for P-256");
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&node[..KEY_LEN]);
        key
    }
}

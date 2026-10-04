//! The cryptographic platform: what the authenticator needs from the device, and the
//! constructions built on it (HKDF, the P-256 private-key range check).
//!
//! The device implements [`Crypto`] with the SDK's `cx` library; host tests and fuzzing use the
//! software implementation behind the `soft` feature.

use zeroize::Zeroizing;

/// Length of a SHA-256 output, an HMAC-SHA-256 tag and an AES-256 key.
pub const KEY_LEN: usize = 32;
/// AES-GCM nonce length (96 bits).
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length (128 bits).
pub const TAG_LEN: usize = 16;
/// AES block length, the length of an AES-CBC initialization vector.
pub const AES_BLOCK_LEN: usize = 16;
/// Uncompressed SEC1 P-256 public key: `0x04 || x || y`.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Longest DER-encoded P-256 ECDSA signature (two 33-byte integers and their headers).
pub const MAX_SIGNATURE_LEN: usize = 72;

/// A failed cryptographic operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// An AEAD tag did not verify: the data or its associated data was altered.
    Authentication,
    /// A private key outside `1..n` of P-256.
    InvalidKey,
    /// A public key that is not a point of P-256.
    InvalidPoint,
    /// AES-CBC data whose length is not a multiple of [`AES_BLOCK_LEN`].
    Length,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            CryptoError::Authentication => "authentication failed",
            CryptoError::InvalidKey => "invalid private key",
            CryptoError::InvalidPoint => "invalid public key",
            CryptoError::Length => "data is not a whole number of AES blocks",
        })
    }
}

/// A DER-encoded ECDSA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; MAX_SIGNATURE_LEN],
    len: usize,
}

impl Signature {
    /// Copies a DER signature of at most [`MAX_SIGNATURE_LEN`] bytes, or `None` for a longer one.
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MAX_SIGNATURE_LEN];
        bytes.get_mut(..der.len())?.copy_from_slice(der);
        Some(Self {
            bytes,
            len: der.len(),
        })
    }

    /// The DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Cryptography of the device. Secrets returned by it are wrapped in [`Zeroizing`]; callers keep
/// derived secrets the same way so every exit path clears them.
pub trait Crypto {
    /// Fills `out` from the true random number generator.
    fn random(&mut self, out: &mut [u8]);

    /// SHA-256 of the concatenation of `parts`, written to `out`. A digest of secrets (a PIN, an
    /// ECDH output) goes straight into the caller's [`Zeroizing`] storage, leaving no copy behind.
    fn sha256_into(&self, parts: &[&[u8]], out: &mut [u8; KEY_LEN]);

    /// SHA-256 of the concatenation of `parts`, for public input such as an RP ID or signed data.
    fn sha256(&self, parts: &[&[u8]]) -> [u8; KEY_LEN] {
        let mut digest = [0u8; KEY_LEN];
        self.sha256_into(parts, &mut digest);
        digest
    }

    /// HMAC-SHA-256 under `key` of the concatenation of `parts` (RFC 2104).
    fn hmac_sha256(&self, key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_LEN]>;

    /// Encrypts `data` in place with AES-256-GCM and returns the tag.
    fn aes256_gcm_seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; TAG_LEN];

    /// Decrypts `data` in place with AES-256-GCM after checking `tag`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Authentication`] when the tag does not verify; `data` is then unspecified
    /// and must be discarded.
    fn aes256_gcm_open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError>;

    /// Encrypts `data` in place with AES-256-CBC from `iv`, without padding.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Length`] when `data` is not a whole number of blocks; `data` is unchanged.
    fn aes256_cbc_encrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; AES_BLOCK_LEN],
        data: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Decrypts `data` in place with AES-256-CBC from `iv`, without padding.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Length`] when `data` is not a whole number of blocks; `data` is unchanged.
    fn aes256_cbc_decrypt(
        &self,
        key: &[u8; KEY_LEN],
        iv: &[u8; AES_BLOCK_LEN],
        data: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// The x-coordinate of `private_key` times the point `peer` (uncompressed SEC1), the shared
    /// secret `Z` of P-256 ECDH (SP 800-56A §5.7.1.2).
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidPoint`] for a `peer` that is not on the curve,
    /// [`CryptoError::InvalidKey`] for a scalar outside `1..n`.
    fn p256_ecdh(
        &self,
        private_key: &[u8; KEY_LEN],
        peer: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError>;

    /// The uncompressed public key of a P-256 private key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a scalar outside `1..n`.
    fn p256_public_key(
        &self,
        private_key: &[u8; KEY_LEN],
    ) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError>;

    /// ECDSA P-256 signature of a SHA-256 `digest`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a scalar outside `1..n`.
    fn p256_sign(
        &mut self,
        private_key: &[u8; KEY_LEN],
        digest: &[u8; KEY_LEN],
    ) -> Result<Signature, CryptoError>;

    /// The private key of the BIP32 node at the application path, derived from the device seed.
    fn application_node(&mut self) -> Zeroizing<[u8; KEY_LEN]>;
}

/// HKDF-SHA-256 (RFC 5869) with a 32-byte output, the first block `T(1)`; an empty `salt` is a
/// string of zeros (RFC 5869 §2.2). The info is `label || suffix`.
pub fn hkdf_sha256<C: Crypto + ?Sized>(
    crypto: &C,
    salt: &[u8],
    ikm: &[u8],
    label: &[u8],
    suffix: &[u8],
) -> Zeroizing<[u8; KEY_LEN]> {
    let zeros = [0u8; KEY_LEN];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    let prk = crypto.hmac_sha256(salt, &[ikm]);
    // T(1) = HMAC(PRK, info || 0x01).
    crypto.hmac_sha256(&prk[..], &[label, suffix, &[0x01]])
}

/// Order `n` of the P-256 group, big-endian (SEC 2 §2.4.2).
const P256_ORDER: [u8; KEY_LEN] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Whether the big-endian `scalar` is a valid P-256 private key, `0 < scalar < n`, in time
/// independent of its value.
pub fn is_p256_private_key(scalar: &[u8; KEY_LEN]) -> bool {
    // `scalar - n` borrows exactly when scalar < n.
    let mut borrow = 0u16;
    let mut any = 0u8;
    for (&s, &n) in scalar.iter().zip(P256_ORDER.iter()).rev() {
        let difference = u16::from(s).wrapping_sub(u16::from(n)).wrapping_sub(borrow);
        // Wrapping: the high byte of a u16 difference is 0xFF exactly when it went negative.
        borrow = difference >> 15;
        any |= s;
    }
    borrow == 1 && any != 0
}

#[cfg(test)]
mod tests;

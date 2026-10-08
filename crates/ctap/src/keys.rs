//! Key hierarchy below the application's BIP32 node (the root key, the credential wrapping key,
//! seed-recoverable credential keys and their hmac-secret values), and the same keys of
//! non-discoverable device-only credentials below the device key `K_dev`.
//!
//! Every key lives in a [`Zeroizing`] buffer for the duration of one command.

use zeroize::Zeroizing;

use crate::crypto::{Crypto, CryptoError, KEY_LEN, hkdf_sha256, is_p256_private_key};

/// Hardened BIP32 index bit.
const HARDENED: u32 = 0x8000_0000;

/// The application path `m/5722689'/5262163'/21328'/0'`: the first two levels are the path the
/// Ledger Security Key application declares, `21328'` (`0x5350`, "SP") separates this
/// application's keys.
pub const APPLICATION_PATH: [u32; 4] = [
    5_722_689 | HARDENED,
    5_262_163 | HARDENED,
    21_328 | HARDENED,
    HARDENED,
];

/// Salt of the root key, naming this application and the version of the hierarchy.
const ROOT_SALT: &[u8] = b"structured-passkeys/v1";

/// The root key `K_root = HKDF-SHA-256(ikm = node, salt = "structured-passkeys/v1", info =
/// "root")`, from which the purpose keys are derived when needed.
pub struct KeyRing {
    root: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyRing")
    }
}

impl KeyRing {
    /// Derives the root key from the application node.
    pub fn new<C: Crypto>(crypto: &mut C) -> Self {
        let node = crypto.application_node();
        Self {
            root: hkdf_sha256(crypto, ROOT_SALT, &node[..], b"root", &[]),
        }
    }

    /// `K_wrap`, the AES-256-GCM key of credential IDs.
    pub fn wrap_key<C: Crypto>(&self, crypto: &C) -> Zeroizing<[u8; KEY_LEN]> {
        hkdf_sha256(crypto, &[], &self.root[..], b"credential-wrap", &[])
    }

    /// The private key of a seed-recoverable credential with credential seed `cs`:
    /// `HKDF-SHA-256(K_cred, salt = cs, info = "es256" || ctr)` for the first one-byte `ctr` from 0
    /// that gives `0 < d < n`. Rejection keeps the key uniform; reducing modulo `n` would bias it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] when all 256 counters are rejected, which happens with
    /// probability below 2^-8000.
    pub fn credential_key<C: Crypto>(
        &self,
        crypto: &C,
        cs: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        credential_key(crypto, &self.root, cs)
    }

    /// The `which` CredRandom of a seed-recoverable credential with credential seed `cs`, for
    /// hmac-secret: `HKDF-SHA-256(K_hmac, salt = cs, info = "uv" | "no-uv")`.
    pub fn cred_random<C: Crypto>(
        &self,
        crypto: &C,
        cs: &[u8; KEY_LEN],
        which: CredRandom,
    ) -> Zeroizing<[u8; KEY_LEN]> {
        cred_random(crypto, &self.root, cs, which)
    }
}

/// Which of a credential's two hmac-secret values (CTAP 2.2 §12.7): the one for ceremonies that
/// verified the user, or the one for ceremonies that did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredRandom {
    /// CredRandomWithUV.
    WithUv,
    /// CredRandomWithoutUV.
    WithoutUv,
}

impl CredRandom {
    /// The value for a response whose UV flag is `uv`.
    pub const fn for_uv(uv: bool) -> Self {
        if uv {
            CredRandom::WithUv
        } else {
            CredRandom::WithoutUv
        }
    }

    const fn info(self) -> &'static [u8] {
        match self {
            CredRandom::WithUv => b"uv",
            CredRandom::WithoutUv => b"no-uv",
        }
    }
}

/// The device key `K_dev`: random, kept only in NVM and erased by reset, so the keys of
/// non-discoverable device-only credentials below it are not reproducible from the recovery
/// phrase.
pub struct DeviceKeys {
    root: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for DeviceKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DeviceKeys")
    }
}

impl DeviceKeys {
    /// Wraps the device key read from NVM.
    pub const fn new(device_key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self { root: device_key }
    }

    /// The private key of a non-discoverable device-only credential with credential seed `cs`:
    /// the seed-recoverable derivation with `K_dev` in place of `K_root`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] when all 256 counters are rejected, which happens with
    /// probability below 2^-8000.
    pub fn credential_key<C: Crypto>(
        &self,
        crypto: &C,
        cs: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        credential_key(crypto, &self.root, cs)
    }

    /// The `which` CredRandom of a non-discoverable device-only credential with credential seed
    /// `cs`: the seed-recoverable derivation with `K_dev` in place of `K_root`.
    pub fn cred_random<C: Crypto>(
        &self,
        crypto: &C,
        cs: &[u8; KEY_LEN],
        which: CredRandom,
    ) -> Zeroizing<[u8; KEY_LEN]> {
        cred_random(crypto, &self.root, cs, which)
    }
}

/// `HKDF-SHA-256(HKDF-SHA-256(root, info = "cred-random"), salt = cs, info = "uv" | "no-uv")`.
fn cred_random<C: Crypto>(
    crypto: &C,
    root: &[u8; KEY_LEN],
    cs: &[u8; KEY_LEN],
    which: CredRandom,
) -> Zeroizing<[u8; KEY_LEN]> {
    let hmac = hkdf_sha256(crypto, &[], &root[..], b"cred-random", &[]);
    hkdf_sha256(crypto, cs, &hmac[..], which.info(), &[])
}

/// `HKDF-SHA-256(HKDF-SHA-256(root, info = "credential-key"), salt = cs, info = "es256" || ctr)`
/// for the first one-byte `ctr` from 0 that gives `0 < d < n`.
fn credential_key<C: Crypto>(
    crypto: &C,
    root: &[u8; KEY_LEN],
    cs: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let credential = hkdf_sha256(crypto, &[], &root[..], b"credential-key", &[]);
    for counter in 0..=u8::MAX {
        let candidate = hkdf_sha256(crypto, cs, &credential[..], b"es256", &[counter]);
        if is_p256_private_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests;

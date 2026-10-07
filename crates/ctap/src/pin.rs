//! PIN/UV auth protocols one and two (CTAP 2.2 §6.5.6, §6.5.7) and the pinUvAuthToken state
//! (§6.5.2.1, §6.5.3.2): key agreement, the shared secret's encrypt, decrypt and verify, and the
//! token with its permissions, permissions RP ID and usage timer.
//!
//! The authenticatorClientPIN command built on them lives in [`crate::ctap2`]; later commands
//! check a `pinUvAuthParam` through [`ClientPin::verify_token`] and the permission checks here.

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    AES_BLOCK_LEN, Crypto, CryptoError, KEY_LEN, PUBLIC_KEY_LEN, hkdf_sha256, is_p256_private_key,
};

/// Length of a pinUvAuthToken: protocol two requires 32 bytes, protocol one allows 16 or 32
/// (§6.5.6, §6.5.7), so one length serves both.
pub const TOKEN_LEN: usize = 32;
/// Length of the PIN hash a platform sends, `LEFT(SHA-256(PIN), 16)` (§6.5.5.6).
pub const PIN_HASH_LEN: usize = 16;
/// Length of a padded PIN (§6.5.5.5: the PIN padded with zeros to 64 bytes).
pub const PADDED_PIN_LEN: usize = 64;
/// Shortest PIN, in Unicode code points (§6.5.1).
pub const MIN_PIN_CODE_POINTS: usize = 4;
/// Longest PIN, in UTF-8 bytes (§6.5.1).
pub const MAX_PIN_BYTES: usize = 63;
/// Longest ciphertext the protocols produce or take here: a padded PIN under protocol two, its
/// IV and 64 bytes.
pub const MAX_CIPHERTEXT_LEN: usize = AES_BLOCK_LEN + PADDED_PIN_LEN;

/// Time a fresh token stays valid without being used: the 30-second USB default maximum of
/// §6.5.2.1. The token is not rolled: once used it stays valid for the max usage time period.
pub const INITIAL_USAGE_TIME_LIMIT_MS: u64 = 30_000;
/// Time user presence collected with a token stays cached, the same default maximum (§6.5.2.1).
pub const USER_PRESENT_TIME_LIMIT_MS: u64 = 30_000;
/// Longest life of a token, the 10-minute default of §6.5.2.1.
pub const MAX_USAGE_TIME_PERIOD_MS: u64 = 600_000;
/// Consecutive PIN mismatches after which PIN operations need a power cycle (§6.5.5.6 step
/// 5.7.1.2.2), here a reopening of the application.
pub const MAX_CONSECUTIVE_MISMATCHES: u8 = 3;

/// A PIN/UV auth protocol (§6.5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// PIN/UV auth protocol one (§6.5.6).
    One = 1,
    /// PIN/UV auth protocol two (§6.5.7).
    Two = 2,
}

impl Protocol {
    /// The protocols in getInfo's `pinUvAuthProtocols` order: platforms take the first they
    /// support (§6.5.5.4 step 1), and two is the one FIPS-approved primitives build.
    pub const SUPPORTED: [Protocol; 2] = [Protocol::Two, Protocol::One];

    /// The protocol numbered `number`, if supported.
    pub const fn from_number(number: u64) -> Option<Self> {
        match number {
            1 => Some(Protocol::One),
            2 => Some(Protocol::Two),
            _ => None,
        }
    }

    /// Length of `authenticate` output and of a valid `pinUvAuthParam`: the first 16 bytes of the
    /// HMAC for protocol one, all 32 for protocol two.
    pub const fn signature_len(self) -> usize {
        match self {
            Protocol::One => 16,
            Protocol::Two => KEY_LEN,
        }
    }

    /// Length of `encrypt(plaintext)`: protocol two prepends its IV.
    pub const fn ciphertext_len(self, plaintext_len: usize) -> usize {
        match self {
            Protocol::One => plaintext_len,
            Protocol::Two => AES_BLOCK_LEN + plaintext_len,
        }
    }

    /// Whether `decrypt` takes a ciphertext of `len` bytes rather than returning an error: whole
    /// AES blocks (§6.5.6), after a 16-byte IV for protocol two (§6.5.7).
    pub const fn decrypts(self, len: usize) -> bool {
        match self {
            Protocol::One => len.is_multiple_of(AES_BLOCK_LEN),
            Protocol::Two => len >= AES_BLOCK_LEN && len.is_multiple_of(AES_BLOCK_LEN),
        }
    }
}

/// pinUvAuthToken permissions (§6.5.5.7), a set of their bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    /// `mc`: authenticatorMakeCredential.
    pub const MAKE_CREDENTIAL: Self = Self(0x01);
    /// `ga`: authenticatorGetAssertion.
    pub const GET_ASSERTION: Self = Self(0x02);
    /// `cm`: authenticatorCredentialManagement.
    pub const CREDENTIAL_MANAGEMENT: Self = Self(0x04);
    /// `be`: authenticatorBioEnrollment.
    pub const BIO_ENROLLMENT: Self = Self(0x08);
    /// `lbw`: authenticatorLargeBlobs writes.
    pub const LARGE_BLOB_WRITE: Self = Self(0x10);
    /// `acfg`: authenticatorConfig.
    pub const AUTHENTICATOR_CONFIG: Self = Self(0x20);
    /// `pcmr`: read-only credential management with the persistent token.
    pub const PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY: Self = Self(0x40);
    /// The defaults getPinToken grants, `mc` and `ga` (§6.5.5.7).
    pub const DEFAULT: Self = Self(0x03);
    /// No permission.
    pub const NONE: Self = Self(0);

    /// The permissions of a request's `permissions` member, keeping only the defined bits:
    /// undefined permissions are ignored (§6.5.5.7.2 steps 4.4 and 4.15).
    pub const fn from_request(bits: u64) -> Self {
        Self((bits & 0x7F) as u8)
    }

    /// The bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every permission of `other` is in this set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether this set and `other` share a permission.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// How a token was obtained, which decides the permissions it may carry (§6.5.5.7.2 step 4,
/// §6.5.5.7.3 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// The client PIN.
    ClientPin,
    /// Built-in user verification.
    BuiltInUv,
}

/// The getInfo option IDs that govern permissions, as this authenticator reports them. Each is
/// false while the feature is not implemented, so a permission for it is refused rather than
/// granted for a command that does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    /// `credMgmt`.
    pub cred_mgmt: bool,
    /// `authnrCfg`.
    pub authnr_cfg: bool,
    /// `uvAcfg`.
    pub uv_acfg: bool,
    /// `largeBlobs`.
    pub large_blobs: bool,
    /// `perCredMgmtRO`.
    pub per_cred_mgmt_ro: bool,
}

impl Features {
    /// Whether `requested` holds a permission that a token obtained with `method` may not carry:
    /// the statements of §6.5.5.7.2 step 4 and §6.5.5.7.3 step 4. `be` is always refused, since
    /// no bioEnroll or uvBioEnroll is reported; `mc` and `ga` are always authorized, since
    /// noMcGaPermissionsWithClientPin is absent.
    pub const fn unauthorized(self, requested: Permissions, method: Method) -> bool {
        let config = match method {
            Method::ClientPin => self.authnr_cfg,
            Method::BuiltInUv => self.uv_acfg,
        };
        (requested.intersects(Permissions::CREDENTIAL_MANAGEMENT) && !self.cred_mgmt)
            || requested.intersects(Permissions::BIO_ENROLLMENT)
            || (requested.intersects(Permissions::LARGE_BLOB_WRITE) && !self.large_blobs)
            || (requested.intersects(Permissions::AUTHENTICATOR_CONFIG) && !config)
            || (requested.intersects(Permissions::PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY)
                && (!self.per_cred_mgmt_ro
                    || requested.bits()
                        != Permissions::PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY.bits()))
    }
}

/// The shared secret of one PIN/UV auth protocol exchange: protocol one keys both HMAC and AES
/// with `SHA-256(Z)`, protocol two derives one key for each with HKDF (§6.5.6 `kdf`, §6.5.7
/// `kdf`). Zeroized on drop.
pub struct SharedSecret {
    protocol: Protocol,
    hmac_key: Zeroizing<[u8; KEY_LEN]>,
    aes_key: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedSecret")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// The shared secret of `protocol` from the ECDH output `z`.
    pub fn new<C: Crypto + ?Sized>(crypto: &C, protocol: Protocol, z: &[u8; KEY_LEN]) -> Self {
        match protocol {
            Protocol::One => {
                let mut key = Zeroizing::new([0u8; KEY_LEN]);
                crypto.sha256_into(&[z], &mut key);
                Self {
                    protocol,
                    hmac_key: key.clone(),
                    aes_key: key,
                }
            }
            // Two separate HKDF invocations with a salt of 32 zero bytes; an empty salt is zeros
            // in `hkdf_sha256`, as RFC 5869 §2.2 defines.
            Protocol::Two => Self {
                protocol,
                hmac_key: hkdf_sha256(crypto, &[], z, b"CTAP2 HMAC key", &[]),
                aes_key: hkdf_sha256(crypto, &[], z, b"CTAP2 AES key", &[]),
            },
        }
    }

    /// The protocol this secret belongs to.
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// `encrypt(plaintext)` into `out`, returning the ciphertext length. Protocol one encrypts
    /// with an all-zero IV, protocol two with a random IV it prepends (§6.5.6, §6.5.7).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Length`] when `plaintext` is not a whole number of AES blocks or `out` is
    /// too short for the ciphertext.
    pub fn encrypt<C: Crypto + ?Sized>(
        &self,
        crypto: &mut C,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let length = self.protocol.ciphertext_len(plaintext.len());
        let out = out.get_mut(..length).ok_or(CryptoError::Length)?;
        let mut iv = [0u8; AES_BLOCK_LEN];
        let body = match self.protocol {
            Protocol::One => out,
            Protocol::Two => {
                crypto.random(&mut iv);
                let (head, body) = out.split_at_mut(AES_BLOCK_LEN);
                head.copy_from_slice(&iv);
                body
            }
        };
        body.copy_from_slice(plaintext);
        if let Err(error) = crypto.aes256_cbc_encrypt(&self.aes_key, &iv, body) {
            // The plaintext copy must not stay behind.
            body.zeroize();
            return Err(error);
        }
        Ok(length)
    }

    /// `decrypt(ciphertext)` into `out`, returning the plaintext length (§6.5.6, §6.5.7). The
    /// caller wipes `out` once it is done with the plaintext.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Length`] for a ciphertext that is not a whole number of blocks, shorter
    /// than protocol two's IV, or longer than `out`.
    pub fn decrypt<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let (iv, body) = match self.protocol {
            Protocol::One => ([0u8; AES_BLOCK_LEN], ciphertext),
            Protocol::Two => {
                let (iv, body) = ciphertext
                    .split_first_chunk::<AES_BLOCK_LEN>()
                    .ok_or(CryptoError::Length)?;
                (*iv, body)
            }
        };
        let out = out.get_mut(..body.len()).ok_or(CryptoError::Length)?;
        out.copy_from_slice(body);
        crypto.aes256_cbc_decrypt(&self.aes_key, &iv, out)?;
        Ok(body.len())
    }

    /// `verify(sharedSecret, message, signature)`: whether `signature` is the protocol's MAC of
    /// the concatenation of `message` under the HMAC key (§6.5.6, §6.5.7).
    pub fn verify<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        verify_mac(crypto, self.protocol, &self.hmac_key, message, signature)
    }
}

/// The protocol's `verify`: the HMAC-SHA-256 of `message` under `key` compared, in time
/// independent of the values, with a signature of exactly the protocol's length (§6.5.6: 16
/// bytes and the first 16 of the HMAC; §6.5.7: all 32).
fn verify_mac<C: Crypto + ?Sized>(
    crypto: &C,
    protocol: Protocol,
    key: &[u8; KEY_LEN],
    message: &[&[u8]],
    signature: &[u8],
) -> bool {
    let length = protocol.signature_len();
    if signature.len() != length {
        return false;
    }
    let mac = crypto.hmac_sha256(key, message);
    let mut difference = 0u8;
    for (&a, &b) in mac[..length].iter().zip(signature) {
        difference |= a ^ b;
    }
    difference == 0
}

/// The state of one protocol: its key agreement key pair and its pinUvAuthToken.
struct ProtocolState {
    private_key: Zeroizing<[u8; KEY_LEN]>,
    public_key: [u8; PUBLIC_KEY_LEN],
    token: Zeroizing<[u8; TOKEN_LEN]>,
}

impl ProtocolState {
    /// `initialize()`: `regenerate` followed by `resetPinUvAuthToken` (§6.5.6).
    fn new<C: Crypto + ?Sized>(crypto: &mut C) -> Self {
        let mut state = Self {
            private_key: Zeroizing::new([0; KEY_LEN]),
            public_key: [0; PUBLIC_KEY_LEN],
            token: Zeroizing::new([0; TOKEN_LEN]),
        };
        state.regenerate(crypto);
        crypto.random(&mut state.token[..]);
        state
    }

    /// `regenerate()`: a fresh, random P-256 key agreement key. Drawn until it is a valid scalar,
    /// so the key is uniform in `1..n`; a draw is rejected with probability below 2^-32.
    fn regenerate<C: Crypto + ?Sized>(&mut self, crypto: &mut C) {
        loop {
            crypto.random(&mut self.private_key[..]);
            if is_p256_private_key(&self.private_key) {
                break;
            }
        }
        self.public_key = crypto
            .p256_public_key(&self.private_key)
            .expect("a scalar in 1..n has a public key");
    }
}

/// The state of the pinUvAuthToken (§6.5.2.1). Its clock is the device's monotonic millisecond
/// count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TokenState {
    in_use: bool,
    permissions: Permissions,
    /// SHA-256 of the permissions RP ID. The hash is kept, not the text: every check compares an
    /// RP ID hash, and authenticatorGetAssertion and authenticatorMakeCredential bind the RP ID
    /// they were given.
    rp_id_hash: Option<[u8; KEY_LEN]>,
    started_ms: u64,
    used: bool,
    user_present: bool,
    user_verified: bool,
}

impl TokenState {
    /// The initial values of §6.5.2.1: not in use, no permission, no RP ID, flags false.
    const INITIAL: Self = Self {
        in_use: false,
        permissions: Permissions::NONE,
        rp_id_hash: None,
        started_ms: 0,
        used: false,
        user_present: false,
        user_verified: false,
    };
}

/// Everything the PIN/UV auth protocols keep in RAM: both protocols' key agreement keys and
/// tokens, the token state, and the count of consecutive PIN mismatches. It lives as long as the
/// application is open; reopening it is the power cycle §6.5.5.6 asks for after three
/// mismatches.
pub struct ClientPin {
    one: ProtocolState,
    two: ProtocolState,
    token: TokenState,
    mismatches: u8,
}

impl core::fmt::Debug for ClientPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ClientPin")
            .field("token", &self.token)
            .field("mismatches", &self.mismatches)
            .finish_non_exhaustive()
    }
}

impl ClientPin {
    /// Power-up: `initialize()` for each supported protocol (§6.5.5.1).
    pub fn new<C: Crypto + ?Sized>(crypto: &mut C) -> Self {
        Self {
            one: ProtocolState::new(crypto),
            two: ProtocolState::new(crypto),
            token: TokenState::INITIAL,
            mismatches: 0,
        }
    }

    fn state(&self, protocol: Protocol) -> &ProtocolState {
        match protocol {
            Protocol::One => &self.one,
            Protocol::Two => &self.two,
        }
    }

    fn state_mut(&mut self, protocol: Protocol) -> &mut ProtocolState {
        match protocol {
            Protocol::One => &mut self.one,
            Protocol::Two => &mut self.two,
        }
    }

    /// `getPublicKey()`: the key agreement public key of `protocol`, uncompressed SEC1.
    pub fn public_key(&self, protocol: Protocol) -> &[u8; PUBLIC_KEY_LEN] {
        &self.state(protocol).public_key
    }

    /// `regenerate()` for `protocol`: a fresh key agreement key, which a PIN mismatch requires
    /// so an attacker cannot keep the shared secret across guesses (§6.5.5.6 step 5.7.1.1).
    pub fn regenerate<C: Crypto + ?Sized>(&mut self, crypto: &mut C, protocol: Protocol) {
        self.state_mut(protocol).regenerate(crypto);
    }

    /// `decapsulate(peerCoseKey)`: the shared secret with the platform key `peer` (§6.5.6
    /// `ecdh`).
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidPoint`] for a peer key that is not on P-256.
    pub fn shared_secret<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        protocol: Protocol,
        peer: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<SharedSecret, CryptoError> {
        let z = crypto.p256_ecdh(&self.state(protocol).private_key, peer)?;
        Ok(SharedSecret::new(crypto, protocol, &z))
    }

    /// The pinUvAuthToken of `protocol`, as `encrypt` sends it to the platform.
    pub fn token(&self, protocol: Protocol) -> &[u8; TOKEN_LEN] {
        &self.state(protocol).token
    }

    /// `resetPinUvAuthToken()` for every protocol: fresh tokens with their state back to the
    /// initial values, so every token issued before stops verifying (§6.5.5.6 step 5.19).
    pub fn reset_tokens<C: Crypto + ?Sized>(&mut self, crypto: &mut C) {
        crypto.random(&mut self.one.token[..]);
        crypto.random(&mut self.two.token[..]);
        self.token = TokenState::INITIAL;
    }

    /// `beginUsingPinUvAuthToken(userIsPresent)` (§6.5.3.2) at `now_ms`, with the token's
    /// `permissions` and permissions RP ID.
    pub fn begin_using(
        &mut self,
        now_ms: u64,
        user_is_present: bool,
        permissions: Permissions,
        rp_id_hash: Option<[u8; KEY_LEN]>,
    ) {
        self.token = TokenState {
            in_use: true,
            permissions,
            rp_id_hash,
            started_ms: now_ms,
            used: false,
            user_present: user_is_present,
            user_verified: true,
        };
    }

    /// `pinUvAuthTokenUsageTimerObserver()` at `now_ms` (§6.5.3.2): the token stops when the
    /// max usage time period passed, or when the initial usage time limit passed before the
    /// platform used it; cached user presence ends after the user present time limit. The
    /// observer runs whenever the token is looked at, which gives the same answers as a timer.
    ///
    /// # Panics
    ///
    /// When `now_ms` is before the time the token was issued: the clock is monotonic.
    pub fn observe(&mut self, now_ms: u64) {
        if !self.token.in_use {
            return;
        }
        let elapsed = now_ms
            .checked_sub(self.token.started_ms)
            .expect("the device clock never runs backwards");
        if elapsed >= MAX_USAGE_TIME_PERIOD_MS
            || (!self.token.used && elapsed >= INITIAL_USAGE_TIME_LIMIT_MS)
        {
            self.token = TokenState::INITIAL;
            return;
        }
        if elapsed >= USER_PRESENT_TIME_LIMIT_MS {
            self.token.user_present = false;
        }
    }

    /// Whether the token is in use at `now_ms`.
    pub fn in_use(&mut self, now_ms: u64) -> bool {
        self.observe(now_ms);
        self.token.in_use
    }

    /// `verify(pinUvAuthToken, message, pinUvAuthParam)` for `protocol` at `now_ms`: false for a
    /// token not in use (§6.5.6 `verify` step 1), else the MAC check. A successful check counts
    /// as the platform using the token, which keeps it past its initial usage time limit.
    pub fn verify_token<C: Crypto + ?Sized>(
        &mut self,
        crypto: &C,
        protocol: Protocol,
        message: &[&[u8]],
        param: &[u8],
        now_ms: u64,
    ) -> bool {
        if !self.in_use(now_ms) {
            return false;
        }
        let verified = verify_mac(crypto, protocol, self.token(protocol), message, param);
        if verified {
            self.token.used = true;
        }
        verified
    }

    /// Whether the token carries every permission of `permission`.
    pub const fn has_permission(&self, permission: Permissions) -> bool {
        self.token.in_use && self.token.permissions.contains(permission)
    }

    /// Whether the token may act for the RP with `rp_id_hash`: it has no permissions RP ID, or
    /// that one. A token without one is bound by [`ClientPin::bind_rp_id`] on its first use with
    /// an RP ID (§6.5.5.7, note on default permissions).
    pub fn permits_rp_id(&self, rp_id_hash: &[u8; KEY_LEN]) -> bool {
        self.token
            .rp_id_hash
            .is_none_or(|bound| constant_time_eq(&bound, rp_id_hash))
    }

    /// Whether the token has a permissions RP ID: credential management subcommands that cover
    /// every RP require a token without one (CTAP 2.2 §6.8.2, §6.8.3).
    pub const fn has_rp_id(&self) -> bool {
        self.token.rp_id_hash.is_some()
    }

    /// Binds the token to `rp_id_hash` unless it has a permissions RP ID; `false` when it is
    /// bound to another RP.
    pub fn bind_rp_id(&mut self, rp_id_hash: &[u8; KEY_LEN]) -> bool {
        if !self.permits_rp_id(rp_id_hash) {
            return false;
        }
        self.token.rp_id_hash = Some(*rp_id_hash);
        true
    }

    /// `getUserPresentFlagValue()` at `now_ms`.
    pub fn user_present(&mut self, now_ms: u64) -> bool {
        self.observe(now_ms);
        self.token.in_use && self.token.user_present
    }

    /// `getUserVerifiedFlagValue()` at `now_ms`.
    pub fn user_verified(&mut self, now_ms: u64) -> bool {
        self.observe(now_ms);
        self.token.in_use && self.token.user_verified
    }

    /// `clearUserPresentFlag()`.
    pub fn clear_user_present(&mut self) {
        self.token.user_present = false;
    }

    /// `clearUserVerifiedFlag()`.
    pub fn clear_user_verified(&mut self) {
        self.token.user_verified = false;
    }

    /// `clearPinUvAuthTokenPermissionsExceptLbw()`: what an operation that tested user presence
    /// does to the token (§6.5.5.7).
    pub fn clear_permissions_except_lbw(&mut self) {
        self.token.permissions =
            Permissions(self.token.permissions.bits() & Permissions::LARGE_BLOB_WRITE.bits());
    }

    /// `stopUsingPinUvAuthToken()`: the token state back to its initial values.
    pub fn stop_using(&mut self) {
        self.token = TokenState::INITIAL;
    }

    /// authenticatorReset (CTAP 2.2 §6.6): new key agreement keys and tokens for both protocols,
    /// the token state back to its initial values, and no mismatches counted, as at power-up.
    pub fn reset<C: Crypto + ?Sized>(&mut self, crypto: &mut C) {
        *self = Self::new(crypto);
    }

    /// Whether PIN operations are blocked until a power cycle: three consecutive mismatches
    /// (§6.5.5.6 step 5.7.1.2.2). getPINRetries reports it as `powerCycleState`.
    pub const fn power_cycle_required(&self) -> bool {
        self.mismatches >= MAX_CONSECUTIVE_MISMATCHES
    }

    /// Counts a PIN mismatch; returns whether it was the third in a row. PIN operations stop
    /// before comparing once three are counted, so the count never passes three.
    pub fn mismatch(&mut self) -> bool {
        debug_assert!(
            !self.power_cycle_required(),
            "blocked operations compare no PIN"
        );
        self.mismatches += 1;
        self.power_cycle_required()
    }

    /// A correct PIN ends a run of mismatches.
    pub fn pin_matched(&mut self) {
        self.mismatches = 0;
    }
}

fn constant_time_eq(left: &[u8; KEY_LEN], right: &[u8; KEY_LEN]) -> bool {
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// The new PIN in `padded` (64 bytes, §6.5.5.5 step 5.7): the bytes before the trailing zeros
/// (step 5.8), checked against the PIN policy (steps 5.9, 5.10). The PIN must be UTF-8, as the
/// platform sends it (§6.5.5.5 step 2.4), at least [`MIN_PIN_CODE_POINTS`] code points and at
/// most [`MAX_PIN_BYTES`] bytes (§6.5.1); `None` violates the policy.
pub fn new_pin(padded: &[u8; PADDED_PIN_LEN]) -> Option<&[u8]> {
    let length = padded
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |last| last + 1);
    let pin = &padded[..length];
    if pin.len() > MAX_PIN_BYTES {
        return None;
    }
    let code_points = core::str::from_utf8(pin).ok()?.chars().count();
    (code_points >= MIN_PIN_CODE_POINTS).then_some(pin)
}

#[cfg(test)]
mod tests;

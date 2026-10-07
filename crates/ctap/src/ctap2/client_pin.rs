//! authenticatorClientPIN (CTAP 2.2 §6.5.5): parsing a request into what its execution needs,
//! and the subcommands.

use alloc::string::String;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::credential::shown_rp_id;
use super::{Authenticator, StatusCode};
use crate::cbor::{self, Decoder, Encoder, Full, Key};
use crate::crypto::{Crypto, KEY_LEN, PUBLIC_KEY_LEN};
use crate::pin::{
    ClientPin, Features, MAX_CIPHERTEXT_LEN, Method, PADDED_PIN_LEN, PIN_HASH_LEN, Permissions,
    Protocol, SharedSecret, TOKEN_LEN, new_pin,
};
use crate::storage::{PIN_RETRIES, PIN_VERIFIER_LEN, PinVerifier, Storage};
use crate::ui::{Answer, Prompt, USER_ACTION_TIMEOUT_MS, Ui};

/// The getInfo option IDs that decide token permissions: credential management and
/// authenticatorConfig are offered, the latter also to a token from built-in user verification
/// (uvAcfg); large blobs and the persistent credential management token are not, so their
/// permissions are refused.
pub const FEATURES: Features = Features {
    cred_mgmt: true,
    authnr_cfg: true,
    uv_acfg: true,
    large_blobs: false,
    per_cred_mgmt_ro: false,
};

/// authenticatorClientPIN subcommands (§6.5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubCommand {
    /// getPINRetries.
    GetPinRetries = 0x01,
    /// getKeyAgreement.
    GetKeyAgreement = 0x02,
    /// setPIN.
    SetPin = 0x03,
    /// changePIN.
    ChangePin = 0x04,
    /// getPinToken.
    GetPinToken = 0x05,
    /// getPinUvAuthTokenUsingUvWithPermissions.
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    /// getUVRetries.
    GetUvRetries = 0x07,
    /// getPinUvAuthTokenUsingPinWithPermissions.
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl SubCommand {
    const fn from_number(number: u64) -> Option<Self> {
        Some(match number {
            0x01 => SubCommand::GetPinRetries,
            0x02 => SubCommand::GetKeyAgreement,
            0x03 => SubCommand::SetPin,
            0x04 => SubCommand::ChangePin,
            0x05 => SubCommand::GetPinToken,
            0x06 => SubCommand::GetPinUvAuthTokenUsingUvWithPermissions,
            0x07 => SubCommand::GetUvRetries,
            0x09 => SubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            _ => return None,
        })
    }
}

/// A byte string member copied out of the request, up to `N` bytes. A longer one keeps no bytes,
/// only its length: no member this command takes is longer than its buffer for a well-formed
/// request. The bytes can be PIN material, so they are wiped on drop and never copied implicitly.
#[derive(Debug, PartialEq, Eq)]
pub struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for Bytes<N> {}

impl<const N: usize> Bytes<N> {
    pub(super) fn new(value: &[u8]) -> Self {
        let mut bytes = [0u8; N];
        if let Some(target) = bytes.get_mut(..value.len()) {
            target.copy_from_slice(value);
        }
        Self {
            bytes,
            len: value.len(),
        }
    }

    /// The bytes, or `None` for a value that did not fit.
    pub fn get(&self) -> Option<&[u8]> {
        self.bytes.get(..self.len)
    }

    /// The length of the value as received, also of one that did not fit.
    pub const fn received_len(&self) -> usize {
        self.len
    }
}

/// The platform key agreement key (`keyAgreement`, a COSE_Key, §6.5.6 `getPublicKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKey {
    /// The point, uncompressed SEC1, not yet checked to be on the curve.
    Point([u8; PUBLIC_KEY_LEN]),
    /// A key that is not an EC2 P-256 key with 32-byte coordinates: `decapsulate` fails on it.
    Unusable,
}

/// The permissions RP ID (`rpId`): its hash for the token, and the text the consent screen shows
/// for it ([`shown_rp_id`]), every character readable and none hiding the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpId {
    hash: [u8; KEY_LEN],
    shown: String,
}

/// An authenticatorClientPIN request, owning its members. Not `Copy`: the byte string members
/// wipe themselves when the one request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientPinRequest {
    protocol: Option<u64>,
    sub_command: u64,
    key_agreement: Option<PeerKey>,
    pin_uv_auth_param: Option<Bytes<KEY_LEN>>,
    new_pin_enc: Option<Bytes<MAX_CIPHERTEXT_LEN>>,
    pin_hash_enc: Option<Bytes<KEY_LEN>>,
    permissions: Option<u64>,
    rp_id: Option<RpId>,
    /// For a setPIN or changePIN whose newPinEnc or pinHashEnc did not fit its buffer: whether
    /// pinUvAuthParam authenticates the members as received, checked while they could still be
    /// read. `None` when nothing was too long or the check could not run (no usable protocol, key
    /// agreement key or shared secret, which execution refuses before it gets to the MAC).
    oversized_mac: Option<bool>,
}

// Every member holding request bytes is a `Bytes`, which wipes itself on drop.
impl ZeroizeOnDrop for ClientPinRequest {}

/// The members a setPIN or changePIN MAC covers, borrowed from the request so that one too long
/// for its buffer can still be authenticated.
#[derive(Default)]
struct Received<'a> {
    pin_uv_auth_param: Option<&'a [u8]>,
    new_pin_enc: Option<&'a [u8]>,
    pin_hash_enc: Option<&'a [u8]>,
}

/// Parses the CBOR parameters of authenticatorClientPIN (§6.5.5). Unknown members are ignored
/// (§8); `subCommand` is the one member every subcommand needs.
pub(super) fn parse<C: Crypto>(
    client_pin: &ClientPin,
    crypto: &C,
    parameters: &[u8],
) -> Result<ClientPinRequest, StatusCode> {
    let mut decoder = Decoder::new(parameters);
    let request = decoder.map(|entries| {
        let mut request = ClientPinRequest {
            protocol: None,
            sub_command: 0,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
            oversized_mac: None,
        };
        let mut received = Received::default();
        let mut sub_command = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => request.protocol = Some(value.unsigned()?),
                Key::Int(0x02) => sub_command = Some(value.unsigned()?),
                Key::Int(0x03) => request.key_agreement = Some(peer_key(value)?),
                Key::Int(0x04) => {
                    let bytes = value.bytes()?;
                    received.pin_uv_auth_param = Some(bytes);
                    request.pin_uv_auth_param = Some(Bytes::new(bytes));
                }
                Key::Int(0x05) => {
                    let bytes = value.bytes()?;
                    received.new_pin_enc = Some(bytes);
                    request.new_pin_enc = Some(Bytes::new(bytes));
                }
                Key::Int(0x06) => {
                    let bytes = value.bytes()?;
                    received.pin_hash_enc = Some(bytes);
                    request.pin_hash_enc = Some(Bytes::new(bytes));
                }
                Key::Int(0x09) => request.permissions = Some(value.unsigned()?),
                Key::Int(0x0A) => {
                    let rp_id = value.text()?;
                    request.rp_id = Some(RpId {
                        hash: crypto.sha256(&[rp_id.as_bytes()]),
                        shown: shown_rp_id(crypto, rp_id),
                    });
                }
                _ => value.skip()?,
            }
        }
        Ok((request, sub_command, received))
    });
    let (mut request, sub_command, received) = request.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    request.sub_command = sub_command.ok_or(StatusCode::MissingParameter)?;
    request.oversized_mac = oversized_mac(client_pin, crypto, &request, &received);
    Ok(request)
}

/// Whether pinUvAuthParam authenticates a setPIN or changePIN whose newPinEnc or pinHashEnc is too
/// long for its buffer. §6.5.5.5 step 5 and §6.5.5.6 step 5.5 verify the MAC over the members as
/// sent before anything looks at their length, so the check runs here, where they can be read.
fn oversized_mac<C: Crypto>(
    client_pin: &ClientPin,
    crypto: &C,
    request: &ClientPinRequest,
    received: &Received<'_>,
) -> Option<bool> {
    let too_long = |member: &Option<Bytes<MAX_CIPHERTEXT_LEN>>| {
        member.as_ref().is_some_and(|bytes| bytes.get().is_none())
    };
    let new_pin_enc = received.new_pin_enc?;
    let message: &[&[u8]] = match SubCommand::from_number(request.sub_command)? {
        SubCommand::SetPin if too_long(&request.new_pin_enc) => &[new_pin_enc],
        SubCommand::ChangePin => {
            let pin_hash_enc = received.pin_hash_enc?;
            let hash_too_long = request
                .pin_hash_enc
                .as_ref()
                .is_some_and(|bytes| bytes.get().is_none());
            if !too_long(&request.new_pin_enc) && !hash_too_long {
                return None;
            }
            &[new_pin_enc, pin_hash_enc]
        }
        _ => return None,
    };
    let protocol = Protocol::from_number(request.protocol?)?;
    let PeerKey::Point(point) = request.key_agreement? else {
        return None;
    };
    let secret = client_pin.shared_secret(crypto, protocol, &point).ok()?;
    Some(secret.verify(
        crypto,
        message,
        received.pin_uv_auth_param.unwrap_or_default(),
    ))
}

/// The status for a newPinEnc that does not decrypt to a padded PIN, once its MAC verified: a
/// length `decrypt` refuses is CTAP2_ERR_PIN_AUTH_INVALID, any other decrypts to other than 64
/// bytes, CTAP1_ERR_INVALID_PARAMETER (§6.5.5.5 steps 6 and 7).
const fn new_pin_length_error(protocol: Protocol, len: usize) -> StatusCode {
    if protocol.decrypts(len) {
        StatusCode::InvalidParameter
    } else {
        StatusCode::PinAuthInvalid
    }
}

/// Reads a COSE_Key (RFC 9052 §7) as the platform key agreement key, parsed as §6.5.6 ecdh
/// requires, "as specified for getPublicKey": kty 2 (EC2), alg -25, crv 1 (P-256), 32-byte x
/// and y, and nothing else: such a key "MUST contain the optional alg parameter and MUST NOT
/// contain any other optional parameters" (§6.5.5, keyAgreement). A key with a further label
/// cannot be decapsulated.
fn peer_key(decoder: &mut Decoder<'_>) -> Result<PeerKey, cbor::Error> {
    decoder.map(|entries| {
        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut other = false;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(1) => kty = Some(value.int()?),
                Key::Int(3) => alg = Some(value.int()?),
                Key::Int(-1) => crv = Some(value.int()?),
                Key::Int(-2) => x = Some(value.bytes()?),
                Key::Int(-3) => y = Some(value.bytes()?),
                _ => {
                    value.skip()?;
                    other = true;
                }
            }
        }
        let point = match (kty, alg, crv, x, y) {
            (Some(2), Some(-25), Some(1), Some(x), Some(y))
                if !other && x.len() == KEY_LEN && y.len() == KEY_LEN =>
            {
                let mut point = [0u8; PUBLIC_KEY_LEN];
                point[0] = 0x04;
                point[1..=KEY_LEN].copy_from_slice(x);
                point[KEY_LEN + 1..].copy_from_slice(y);
                PeerKey::Point(point)
            }
            _ => PeerKey::Unusable,
        };
        Ok(point)
    })
}

/// Writes the key agreement public key as the COSE_Key of §6.5.6 `getPublicKey`: kty 2, alg
/// -25, crv 1, x, y, keys in canonical order.
fn write_cose_key(encoder: &mut Encoder<'_>, point: &[u8; PUBLIC_KEY_LEN]) -> Result<(), Full> {
    encoder
        .map(5)?
        .unsigned(1)?
        .unsigned(2)?
        .unsigned(3)?
        .int(-25)?
        .int(-1)?
        .unsigned(1)?
        .int(-2)?
        .bytes(&point[1..=KEY_LEN])?
        .int(-3)?
        .bytes(&point[KEY_LEN + 1..])?;
    Ok(())
}

/// The members a subcommand requires, or CTAP2_ERR_MISSING_PARAMETER (§6.5.5.5 step 5.1 and its
/// counterparts).
fn required<T>(member: Option<T>) -> Result<T, StatusCode> {
    member.ok_or(StatusCode::MissingParameter)
}

/// The permissions RP ID is a mandatory parameter when the requested `bits` include mc or ga
/// (CTAP 2.2 §6.5.5.7, RP ID "Required" for both), so its absence is
/// CTAP2_ERR_MISSING_PARAMETER (§6.5.5.7.2 and §6.5.5.7.3 step 1). Only getPinToken's default
/// permissions are bound by their first use.
fn rp_id_present(bits: u64, request: &ClientPinRequest) -> Result<(), StatusCode> {
    let rp_scoped =
        u64::from(Permissions::MAKE_CREDENTIAL.bits() | Permissions::GET_ASSERTION.bits());
    if bits & rp_scoped != 0 && request.rp_id.is_none() {
        return Err(StatusCode::MissingParameter);
    }
    Ok(())
}

/// The selected protocol, or CTAP1_ERR_INVALID_PARAMETER for one not supported (§6.5.5.4 step 4).
fn protocol(number: u64) -> Result<Protocol, StatusCode> {
    Protocol::from_number(number).ok_or(StatusCode::InvalidParameter)
}

/// The shared secret with the platform key, or CTAP1_ERR_INVALID_PARAMETER when `decapsulate`
/// fails (§6.5.5.5 step 5.4).
fn decapsulate<C: Crypto>(
    client_pin: &ClientPin,
    crypto: &C,
    protocol: Protocol,
    peer: PeerKey,
) -> Result<SharedSecret, StatusCode> {
    match peer {
        PeerKey::Point(point) => client_pin
            .shared_secret(crypto, protocol, &point)
            .map_err(|_| StatusCode::InvalidParameter),
        PeerKey::Unusable => Err(StatusCode::InvalidParameter),
    }
}

/// The answer to a consent screen: approval goes on; a refusal or no answer is consent not
/// approved, CTAP2_ERR_OPERATION_DENIED (§6.5.5.7.1 and §6.5.5.7.2 step 7); a request the host
/// cancelled is CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5).
pub(super) fn consent(answer: Answer) -> Result<(), StatusCode> {
    match answer {
        Answer::Confirmed => Ok(()),
        Answer::Rejected | Answer::TimedOut => Err(StatusCode::OperationDenied),
        Answer::Cancelled => Err(StatusCode::KeepaliveCancel),
    }
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs an authenticatorClientPIN request, writing its response map into `encoder`.
    pub(super) fn client_pin<U: Ui>(
        &mut self,
        request: &ClientPinRequest,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        // §6.5.5: a subCommand the authenticator does not know is CTAP2_ERR_INVALID_SUBCOMMAND.
        let sub_command =
            SubCommand::from_number(request.sub_command).ok_or(StatusCode::InvalidSubcommand)?;
        match sub_command {
            SubCommand::GetPinRetries => self.get_pin_retries(encoder),
            SubCommand::GetKeyAgreement => {
                let protocol = protocol(required(request.protocol)?)?;
                write_full(encoder.map(1).and_then(|encoder| encoder.unsigned(0x01)))?;
                write_full(write_cose_key(
                    encoder,
                    self.client_pin.public_key(protocol),
                ))
            }
            SubCommand::SetPin => self.set_pin(request),
            SubCommand::ChangePin => self.change_pin(request),
            SubCommand::GetPinToken => self.get_pin_token(request, ui, encoder),
            SubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                self.get_pin_token(request, ui, encoder)
            }
            SubCommand::GetPinUvAuthTokenUsingUvWithPermissions => {
                self.get_token_using_uv(request, ui, encoder)
            }
            SubCommand::GetUvRetries => {
                let retries = self.uv_retries(ui);
                write_full(
                    encoder
                        .map(1)
                        .and_then(|encoder| encoder.unsigned(0x05))
                        .and_then(|encoder| encoder.unsigned(u64::from(retries))),
                )
            }
        }
    }

    /// getPINRetries (§6.5.5.2): `pinRetries` and `powerCycleState`.
    fn get_pin_retries(&self, encoder: &mut Encoder<'_>) -> Result<(), StatusCode> {
        let retries = self.store.config().pin_retries;
        write_full(
            encoder
                .map(2)
                .and_then(|encoder| encoder.unsigned(0x03))
                .and_then(|encoder| encoder.unsigned(u64::from(retries)))
                .and_then(|encoder| encoder.unsigned(0x04))
                .and_then(|encoder| encoder.bool(self.client_pin.power_cycle_required())),
        )
    }

    /// `uvRetries` (§6.5.2.3) with built-in UV as the device unlock, which cannot fail: 1 while
    /// the device PIN is validated, none once the client PIN is blocked, since a blocked PIN
    /// disables built-in user verification too (performBuiltInUv step 3), and none on a device
    /// the operating system does not hold unlocked.
    pub(super) fn uv_retries<U: Ui>(&self, ui: &mut U) -> u8 {
        let config = self.store.config();
        if config.pin.is_some() && config.pin_retries == 0 {
            return 0;
        }
        u8::from(ui.device_unlocked())
    }

    /// setPIN (§6.5.5.5).
    fn set_pin(&mut self, request: &ClientPinRequest) -> Result<(), StatusCode> {
        let number = required(request.protocol)?;
        let peer = required(request.key_agreement)?;
        let new_pin_enc = required(request.new_pin_enc.as_ref())?;
        let param = required(request.pin_uv_auth_param.as_ref())?;
        let protocol = protocol(number)?;
        if self.store.config().pin.is_some() {
            return Err(StatusCode::PinAuthInvalid);
        }
        let secret = decapsulate(&self.client_pin, &self.crypto, protocol, peer)?;
        // A newPinEnc longer than a padded PIN's ciphertext was authenticated while parsing;
        // with a valid MAC it fails decryption or decrypts to more than 64 bytes.
        let Some(new_pin_enc_bytes) = new_pin_enc.get() else {
            if request.oversized_mac != Some(true) {
                return Err(StatusCode::PinAuthInvalid);
            }
            return Err(new_pin_length_error(protocol, new_pin_enc.received_len()));
        };
        if !secret.verify(
            &self.crypto,
            &[new_pin_enc_bytes],
            param.get().unwrap_or_default(),
        ) {
            return Err(StatusCode::PinAuthInvalid);
        }
        let verifier = self.new_pin_verifier(&secret, new_pin_enc_bytes)?;
        let mut config = self.store.config();
        config.pin = Some(verifier);
        config.pin_retries = PIN_RETRIES;
        self.store.write_config(&config);
        Ok(())
    }

    /// changePIN (§6.5.5.6).
    fn change_pin(&mut self, request: &ClientPinRequest) -> Result<(), StatusCode> {
        let number = required(request.protocol)?;
        let peer = required(request.key_agreement)?;
        let pin_hash_enc = required(request.pin_hash_enc.as_ref())?;
        let new_pin_enc = required(request.new_pin_enc.as_ref())?;
        let param = required(request.pin_uv_auth_param.as_ref())?;
        let protocol = protocol(number)?;
        self.pin_usable()?;
        let secret = decapsulate(&self.client_pin, &self.crypto, protocol, peer)?;
        // A member longer than its buffer was authenticated while parsing.
        let authenticated = match (new_pin_enc.get(), pin_hash_enc.get()) {
            (Some(new_pin_enc), Some(pin_hash_enc)) => secret.verify(
                &self.crypto,
                &[new_pin_enc, pin_hash_enc],
                param.get().unwrap_or_default(),
            ),
            _ => request.oversized_mac == Some(true),
        };
        if !authenticated {
            return Err(StatusCode::PinAuthInvalid);
        }
        // A pinHashEnc too long for a PIN hash is a mismatch: it spends the try (steps 5.6 to
        // 5.8) like any other wrong PIN.
        self.check_pin_hash(&secret, pin_hash_enc.get().unwrap_or_default())?;
        let Some(new_pin_enc) = new_pin_enc.get() else {
            return Err(new_pin_length_error(protocol, new_pin_enc.received_len()));
        };
        let verifier = self.new_pin_verifier(&secret, new_pin_enc)?;
        let mut config = self.store.config();
        config.pin = Some(verifier);
        config.pin_retries = PIN_RETRIES;
        self.store.write_config(&config);
        // Every token issued before stops working (step 5.19).
        self.client_pin.reset_tokens(&mut self.crypto);
        Ok(())
    }

    /// getPinToken (§6.5.5.7.1) and getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2).
    fn get_pin_token<U: Ui>(
        &mut self,
        request: &ClientPinRequest,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let with_permissions =
            request.sub_command == SubCommand::GetPinUvAuthTokenUsingPinWithPermissions as u64;
        let number = required(request.protocol)?;
        let peer = required(request.key_agreement)?;
        let pin_hash_enc = required(request.pin_hash_enc.as_ref())?;
        let permissions = if with_permissions {
            let bits = required(request.permissions)?;
            rp_id_present(bits, request)?;
            Some(bits)
        } else {
            None
        };
        let protocol = protocol(number)?;
        let permissions = match permissions {
            Some(bits) => {
                if bits == 0 {
                    return Err(StatusCode::InvalidParameter);
                }
                let permissions = Permissions::from_request(bits);
                if FEATURES.unauthorized(permissions, Method::ClientPin) {
                    return Err(StatusCode::UnauthorizedPermission);
                }
                permissions
            }
            // getPinToken takes neither permissions nor an RP ID (§6.5.5.7.1).
            None => {
                if request.permissions.is_some() || request.rp_id.is_some() {
                    return Err(StatusCode::InvalidParameter);
                }
                Permissions::DEFAULT
            }
        };
        self.pin_usable()?;
        let secret = decapsulate(&self.client_pin, &self.crypto, protocol, peer)?;
        consent(ui.confirm(
            Prompt::Token {
                permissions,
                rp_id: request.rp_id.as_ref().map(|rp_id| rp_id.shown.as_str()),
            },
            USER_ACTION_TIMEOUT_MS,
        ))?;
        let pin_hash_enc = pin_hash_enc.get().unwrap_or_default();
        self.check_pin_hash(&secret, pin_hash_enc)?;
        // forcePINChange is never set: no command here lowers the minimum PIN length.
        self.client_pin.reset_tokens(&mut self.crypto);
        let now_ms = ui.now_ms();
        self.client_pin.begin_using(
            now_ms,
            false,
            permissions,
            request.rp_id.as_ref().map(|rp_id| rp_id.hash),
        );
        self.write_token(&secret, encoder)
    }

    /// getPinUvAuthTokenUsingUvWithPermissions (§6.5.5.7.3): built-in UV is the device PIN the
    /// person entered to unlock the device, which the operating system holds validated.
    fn get_token_using_uv<U: Ui>(
        &mut self,
        request: &ClientPinRequest,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let number = required(request.protocol)?;
        let peer = required(request.key_agreement)?;
        let bits = required(request.permissions)?;
        rp_id_present(bits, request)?;
        let protocol = protocol(number)?;
        if bits == 0 {
            return Err(StatusCode::InvalidParameter);
        }
        let permissions = Permissions::from_request(bits);
        if FEATURES.unauthorized(permissions, Method::BuiltInUv) {
            return Err(StatusCode::UnauthorizedPermission);
        }
        if self.uv_retries(ui) == 0 {
            return Err(StatusCode::UvBlocked);
        }
        // Checked before any screen, so a request with an unusable key never asks the user.
        let secret = decapsulate(&self.client_pin, &self.crypto, protocol, peer)?;
        // Step 9: consent to the requested permissions.
        consent(ui.confirm(
            Prompt::Token {
                permissions,
                rp_id: request.rp_id.as_ref().map(|rp_id| rp_id.shown.as_str()),
            },
            USER_ACTION_TIMEOUT_MS,
        ))?;
        // Step 10, performBuiltInUv: the unlock is the verification, so it succeeds unless the
        // device was locked meanwhile, which leaves no attempt (step 11, UV_BLOCKED).
        if !ui.device_unlocked() {
            return Err(StatusCode::UvBlocked);
        }
        self.client_pin.reset_tokens(&mut self.crypto);
        // The consent tap on the device is evidence of user interaction (step 14).
        let now_ms = ui.now_ms();
        self.client_pin.begin_using(
            now_ms,
            true,
            permissions,
            request.rp_id.as_ref().map(|rp_id| rp_id.hash),
        );
        self.write_token(&secret, encoder)
    }

    /// The checks every PIN-entry subcommand makes before it spends a try: a PIN is set, it is
    /// not blocked (CTAP2_ERR_PIN_BLOCKED, §6.5.5.6 step 5.3), and no three mismatches wait for
    /// a power cycle (CTAP2_ERR_PIN_AUTH_BLOCKED, step 5.7.1.2.2).
    fn pin_usable(&self) -> Result<(), StatusCode> {
        let config = self.store.config();
        if config.pin.is_none() {
            // §6.5.5 lists no step for a PIN entry without a PIN; CTAP2_ERR_PIN_NOT_SET (§8.2)
            // says what is wrong, and no try is spent on it.
            return Err(StatusCode::PinNotSet);
        }
        if config.pin_retries == 0 {
            return Err(StatusCode::PinBlocked);
        }
        if self.client_pin.power_cycle_required() {
            return Err(StatusCode::PinAuthBlocked);
        }
        Ok(())
    }

    /// Spends a PIN try and checks `pinHashEnc` against the stored verifier (§6.5.5.6 steps
    /// 5.6 to 5.8). The try is written before the comparison, so cutting power cannot save it.
    /// A mismatch regenerates the key agreement key and answers CTAP2_ERR_PIN_BLOCKED,
    /// CTAP2_ERR_PIN_AUTH_BLOCKED or CTAP2_ERR_PIN_INVALID; a match restores the tries.
    fn check_pin_hash(
        &mut self,
        secret: &SharedSecret,
        pin_hash_enc: &[u8],
    ) -> Result<(), StatusCode> {
        let mut config = self.store.config();
        config.pin_retries = config
            .pin_retries
            .checked_sub(1)
            .expect("pin_usable refuses a blocked PIN");
        self.store.write_config(&config);
        let mut pin_hash = Zeroizing::new([0u8; KEY_LEN]);
        let matched = match secret.decrypt(&self.crypto, pin_hash_enc, &mut pin_hash[..]) {
            Ok(PIN_HASH_LEN) => {
                let mut candidate = [0u8; PIN_VERIFIER_LEN];
                candidate.copy_from_slice(&pin_hash[..PIN_HASH_LEN]);
                let matched = config
                    .pin
                    .as_ref()
                    .is_some_and(|verifier| verifier.matches(&candidate));
                candidate.zeroize();
                matched
            }
            // A ciphertext of another length is a decrypt error or a wrong value: a mismatch.
            Ok(_) | Err(_) => false,
        };
        if !matched {
            self.client_pin
                .regenerate(&mut self.crypto, secret.protocol());
            if config.pin_retries == 0 {
                return Err(StatusCode::PinBlocked);
            }
            return Err(if self.client_pin.mismatch() {
                StatusCode::PinAuthBlocked
            } else {
                StatusCode::PinInvalid
            });
        }
        self.client_pin.pin_matched();
        config.pin_retries = PIN_RETRIES;
        self.store.write_config(&config);
        Ok(())
    }

    /// Decrypts `newPinEnc` and turns the PIN into its stored verifier `LEFT(SHA-256(newPin),
    /// 16)` (§6.5.5.5 steps 5.6 to 5.12).
    fn new_pin_verifier(
        &self,
        secret: &SharedSecret,
        new_pin_enc: &[u8],
    ) -> Result<PinVerifier, StatusCode> {
        let mut padded = Zeroizing::new([0u8; PADDED_PIN_LEN]);
        let length = secret
            .decrypt(&self.crypto, new_pin_enc, &mut padded[..])
            .map_err(|_| new_pin_length_error(secret.protocol(), new_pin_enc.len()))?;
        if length != PADDED_PIN_LEN {
            return Err(StatusCode::InvalidParameter);
        }
        let pin = new_pin(&padded).ok_or(StatusCode::PinPolicyViolation)?;
        let mut hash = Zeroizing::new([0u8; KEY_LEN]);
        self.crypto.sha256_into(&[pin], &mut hash);
        let mut verifier = [0u8; PIN_VERIFIER_LEN];
        verifier.copy_from_slice(&hash[..PIN_VERIFIER_LEN]);
        let stored = PinVerifier::new(verifier);
        verifier.zeroize();
        Ok(stored)
    }

    /// The response of a token-issuing subcommand: `encrypt(sharedSecret, pinUvAuthToken)`.
    fn write_token(
        &mut self,
        secret: &SharedSecret,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let mut encrypted = Zeroizing::new([0u8; MAX_CIPHERTEXT_LEN]);
        // Borrowed in place: a copy of the token would stay on the stack.
        let token: &[u8; TOKEN_LEN] = self.client_pin.token(secret.protocol());
        let length = secret
            .encrypt(&mut self.crypto, token, &mut encrypted[..])
            .map_err(|_| StatusCode::Other)?;
        write_full(
            encoder
                .map(1)
                .and_then(|encoder| encoder.unsigned(0x02))
                .and_then(|encoder| encoder.bytes(&encrypted[..length])),
        )
    }
}

/// A response that does not fit the buffer is CTAP1_ERR_OTHER.
pub(super) fn write_full<T>(result: Result<T, Full>) -> Result<(), StatusCode> {
    result.map(|_| ()).map_err(|Full| StatusCode::Other)
}

#[cfg(test)]
pub(super) mod tests;

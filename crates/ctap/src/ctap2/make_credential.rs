//! authenticatorMakeCredential (CTAP 2.2 §6.1): parsing a request into what its execution
//! needs, and the algorithm of §6.1.2.

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use super::client_pin::{Bytes, write_full};
use super::credential::{
    AT, Options, PUBLIC_KEY, authenticator_data, descriptors, flags, options, presence, shown,
    shown_rp_id,
};
use super::{Authenticator, Link, StatusCode};
use crate::attestation::{ES256, encode_packed_statement, sign_self_attestation};
use crate::cbor::{Decoder, Encoder, Key};
use crate::credential_id::{
    self, CredProtect, Credential, KeySource, MAX_NAME_LEN, MAX_USER_ID_LEN, Origin, SEED_LEN,
    SealError, User,
};
use crate::crypto::{Crypto, KEY_LEN, PUBLIC_KEY_LEN, is_p256_private_key};
use crate::keys::{DeviceKeys, KeyRing};
use crate::pin::Permissions;
use crate::storage::{DeviceKey, Reservation, Storage};
use crate::ui::{Account, Choice, Prompt, Registration, USER_ACTION_TIMEOUT_MS, Ui};

/// The `user` member (WebAuthn L3 §5.4.3): the user handle and the names the relying party gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserEntity {
    /// `id`, the user handle.
    pub id: Vec<u8>,
    /// `name`.
    pub name: Option<String>,
    /// `displayName`.
    pub display_name: Option<String>,
}

/// An authenticatorMakeCredential request, owning its members. Not `Clone`: its
/// `pinUvAuthParam` wipes itself when the one request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    client_data_hash: [u8; KEY_LEN],
    rp_id: String,
    user: UserEntity,
    /// The algorithm pubKeyCredParams chose, `None` when it lists none this authenticator has.
    algorithm: Option<i64>,
    exclude_list: Vec<Vec<u8>>,
    options: Options,
    pin_uv_auth_param: Option<Bytes<KEY_LEN>>,
    pin_uv_auth_protocol: Option<u64>,
    enterprise_attestation: bool,
    /// attestationFormatsPreference is the single format `none`.
    attestation_none: bool,
}

/// Reads `rp` (WebAuthn L3 §5.4.2): its `id`, the RP ID. `name` is not kept, but as a known member
/// it must be a text string (CTAP 2.2 §6.1.2 step 3.1.2); the removed `icon`, which authenticators
/// "MUST NOT error" on (§6.1, rp), and any other member are skipped.
fn rp_entity<'a>(decoder: &mut Decoder<'a>) -> Result<Option<&'a str>, crate::cbor::Error> {
    decoder.map(|entries| {
        let mut id = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text("id") => id = Some(value.text()?),
                Key::Text("name") => {
                    value.text()?;
                }
                _ => value.skip()?,
            }
        }
        Ok(id)
    })
}

/// Reads `user` (WebAuthn L3 §5.4.3); `None` without its `id`. The removed `icon` member and any
/// other are skipped (§6.1, note on `user`).
pub(super) fn user_entity(
    decoder: &mut Decoder<'_>,
) -> Result<Option<UserEntity>, crate::cbor::Error> {
    decoder.map(|entries| {
        let mut id = None;
        let mut name = None;
        let mut display_name = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text("id") => id = Some(value.bytes()?.to_vec()),
                Key::Text("name") => name = Some(String::from(value.text()?)),
                Key::Text("displayName") => display_name = Some(String::from(value.text()?)),
                _ => value.skip()?,
            }
        }
        Ok(id.map(|id| UserEntity {
            id,
            name,
            display_name,
        }))
    })
}

/// Reads pubKeyCredParams (§6.1.2 step 3): every element is read and checked, and the first one
/// of type `public-key` with an algorithm this authenticator supports (ES256) is chosen. An
/// element without `type` or `alg` sets `missing`.
fn algorithm(
    decoder: &mut Decoder<'_>,
    missing: &mut bool,
) -> Result<Option<i64>, crate::cbor::Error> {
    decoder.array(|elements| {
        let mut chosen = None;
        while let Some(element) = elements.next_element() {
            let (alg, kind) = element.map(|entries| {
                let mut alg = None;
                let mut kind = None;
                while let Some(key) = entries.next_key()? {
                    let value = entries.value();
                    match key {
                        Key::Text("alg") => alg = Some(value.int()?),
                        Key::Text("type") => kind = Some(value.text()?),
                        _ => value.skip()?,
                    }
                }
                Ok((alg, kind))
            })?;
            match (alg, kind) {
                (Some(ES256), Some(PUBLIC_KEY)) => {
                    chosen.get_or_insert(ES256);
                }
                (Some(_), Some(_)) => {}
                _ => *missing = true,
            }
        }
        Ok(chosen)
    })
}

/// Reads attestationFormatsPreference: whether `none` comes before `packed`, the two supported
/// formats, so the attestation is left out (§6.1.2: the supported format "with the lowest index in
/// the supplied array"). A list naming neither keeps the default, packed.
fn attestation_none(decoder: &mut Decoder<'_>) -> Result<bool, crate::cbor::Error> {
    decoder.array(|elements| {
        let mut chosen = None;
        while let Some(element) = elements.next_element() {
            // Every element is read, so a malformed later one is still refused.
            let format = element.text()?;
            if chosen.is_none() && matches!(format, "none" | "packed") {
                chosen = Some(format == "none");
            }
        }
        Ok(chosen.unwrap_or(false))
    })
}

/// Parses the CBOR parameters of authenticatorMakeCredential (§6.1). Unknown members are ignored
/// (§8); clientDataHash, rp, user and pubKeyCredParams are required.
pub(super) fn parse(parameters: &[u8]) -> Result<MakeCredentialRequest, StatusCode> {
    let mut decoder = Decoder::new(parameters);
    let mut missing = false;
    let parsed = decoder.map(|entries| {
        let mut client_data_hash = None;
        let mut rp_id = None;
        let mut user = None;
        let mut algorithm_chosen = None;
        let mut exclude_list = Vec::new();
        let mut request_options = Options::default();
        let mut pin_uv_auth_param = None;
        let mut pin_uv_auth_protocol = None;
        let mut enterprise_attestation = false;
        let mut none = false;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => client_data_hash = Some(value.bytes()?),
                Key::Int(0x02) => rp_id = Some(rp_entity(value)?),
                Key::Int(0x03) => user = Some(user_entity(value)?),
                Key::Int(0x04) => algorithm_chosen = Some(algorithm(value, &mut missing)?),
                // §6.1 says a present excludeList "MUST NOT be empty", a rule for the platform:
                // no step of §6.1.2 nor §8 gives the authenticator an error for it. An empty list
                // excludes nothing, as an omitted one, so it is accepted rather than failing a
                // registration that loses nothing by going ahead.
                Key::Int(0x05) => exclude_list = descriptors(value, &mut missing)?,
                // An extension this authenticator does not support is ignored (§6.1.2 step
                // 19.1); the member must still be a map.
                Key::Int(0x06) => value.map(|_| Ok(()))?,
                Key::Int(0x07) => request_options = options(value)?,
                Key::Int(0x08) => pin_uv_auth_param = Some(Bytes::new(value.bytes()?)),
                Key::Int(0x09) => pin_uv_auth_protocol = Some(value.unsigned()?),
                Key::Int(0x0A) => {
                    value.unsigned()?;
                    enterprise_attestation = true;
                }
                Key::Int(0x0B) => none = attestation_none(value)?,
                _ => value.skip()?,
            }
        }
        Ok((
            client_data_hash,
            rp_id,
            user,
            algorithm_chosen,
            exclude_list,
            request_options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            enterprise_attestation,
            none,
        ))
    });
    let (
        client_data_hash,
        rp_id,
        user,
        algorithm_chosen,
        exclude_list,
        request_options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
        enterprise_attestation,
        attestation_none,
    ) = parsed.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    let (Some(client_data_hash), Some(Some(rp_id)), Some(Some(user)), Some(algorithm)) =
        (client_data_hash, rp_id, user, algorithm_chosen)
    else {
        return Err(StatusCode::MissingParameter);
    };
    if missing {
        return Err(StatusCode::MissingParameter);
    }
    // WebAuthn L3 §5.8.1: the hash of the client data is SHA-256, 32 bytes.
    let client_data_hash = client_data_hash
        .try_into()
        .map_err(|_| StatusCode::InvalidLength)?;
    Ok(MakeCredentialRequest {
        client_data_hash,
        rp_id: String::from(rp_id),
        user,
        algorithm,
        exclude_list,
        options: request_options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
        enterprise_attestation,
        attestation_none,
    })
}

/// The account a registration screen shows for `user`: its names as received, at most the
/// length the credential stores, made safe for the screen.
fn names(user: &UserEntity) -> (Option<String>, Option<String>) {
    (
        user.name.as_deref().map(|name| shown(name, MAX_NAME_LEN)),
        user.display_name
            .as_deref()
            .map(|name| shown(name, MAX_NAME_LEN)),
    )
}

/// A new credential: its ID, public key and private key.
struct Created {
    id: Vec<u8>,
    public_key: [u8; PUBLIC_KEY_LEN],
    private_key: Zeroizing<[u8; KEY_LEN]>,
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs an authenticatorMakeCredential request that arrived on `link` (§6.1.2), writing its
    /// response map into `encoder`.
    pub(super) fn make_credential<U: Ui>(
        &mut self,
        request: &MakeCredentialRequest,
        link: Link,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let now_ms = ui.now_ms();
        // Step 1: a zero-length pinUvAuthParam asks for evidence of user interaction.
        if request
            .pin_uv_auth_param
            .as_ref()
            .is_some_and(|param| param.received_len() == 0)
        {
            return Err(self.probe(link, ui));
        }
        // Step 2.
        let protocol = match request.pin_uv_auth_param {
            Some(_) => Some(Self::param_protocol(request.pin_uv_auth_protocol)?),
            None => None,
        };
        // Step 3.
        let alg = request.algorithm.ok_or(StatusCode::UnsupportedAlgorithm)?;
        // Step 5: pinUvAuthParam takes precedence over the uv option. Built-in user verification
        // is the device unlock, supported and enabled, so a true uv option is never invalid.
        let mut uv_option = protocol.is_none() && request.options.uv == Some(true);
        let rk = request.options.rk.unwrap_or(false);
        if request.options.up == Some(false) {
            return Err(StatusCode::InvalidOption);
        }
        let config = self.store.config();
        // Step 6: under alwaysUv, a request without pinUvAuthParam gets built-in user
        // verification, which this authenticator always offers (uv option ID true).
        if config.always_uv && protocol.is_none() {
            uv_option = true;
        }
        // Step 8 (makeCredUvNotRqd is false): the authenticator is protected by built-in user
        // verification, so a credential without some form of it is refused.
        if !uv_option && protocol.is_none() {
            return Err(if config.pin.is_some() {
                StatusCode::PuatRequired
            } else {
                StatusCode::OperationDenied
            });
        }
        // Step 9: no enterprise attestation.
        if request.enterprise_attestation {
            return Err(StatusCode::InvalidParameter);
        }
        // A discoverable credential stores the user handle, at most 64 bytes (WebAuthn L3
        // §5.4.3), refused before anything asks the user; an empty one is valid (CTAP 2.2 §6.1,
        // user: "an empty account identifier is valid"). CTAP sets the authenticator no length
        // for user.id, the 64 bytes being the client's check (WebAuthn L3 §5.1.3 step 5), and a
        // non-discoverable credential keeps no handle, so only the stored one is bounded here.
        if rk && request.user.id.len() > MAX_USER_ID_LEN {
            return Err(StatusCode::InvalidParameter);
        }
        let rp_id_hash = self.crypto.sha256(&[request.rp_id.as_bytes()]);
        // Step 11: user verification.
        if let (Some(protocol), Some(param)) = (protocol, &request.pin_uv_auth_param) {
            self.verify_param(
                protocol,
                param.get().unwrap_or_default(),
                &request.client_data_hash,
                Permissions::MAKE_CREDENTIAL,
                &rp_id_hash,
                now_ms,
            )?;
        } else {
            self.built_in_uv(ui)?;
        }
        // Every path that gets here verified the user.
        let uv = true;
        let keys = KeyRing::new(&mut self.crypto);
        let shown_rp = shown_rp_id(&self.crypto, &request.rp_id);
        // Step 16: a credential of the excludeList is reported only after user presence, so the
        // answer cannot probe for registrations unnoticed. Credentials are created with
        // credProtect level 1, so none is skipped for want of user verification.
        for id in &request.exclude_list {
            let Some(credential) = self.locate(&keys, &request.rp_id, id) else {
                continue;
            };
            if credential.cred_protect == CredProtect::Required && !uv {
                continue;
            }
            if self.nfc_tap_unused(link, now_ms) {
                // The tap was this operation's presence, so it is used like a registration's.
                self.use_nfc_tap();
            } else {
                // Step 16.1.4.2: excluded whether presence came or the wait timed out.
                let answer = ui.confirm(
                    Prompt::Excluded {
                        rp_id: shown_rp.as_str(),
                    },
                    USER_ACTION_TIMEOUT_MS,
                );
                if answer == crate::ui::Answer::Cancelled {
                    return Err(StatusCode::KeepaliveCancel);
                }
            }
            return Err(StatusCode::CredentialExcluded);
        }
        // Step 18: user presence, with the key origin chosen on the screen. The default is
        // device-only for a discoverable credential with user verification, the request a
        // relying party makes when its policy is that the credential stays on the device;
        // seed-recoverable otherwise. Over NFC the tap is the presence and no screen is shown,
        // so the default holds.
        let default_origin = if rk && uv {
            Origin::DeviceOnly
        } else {
            Origin::SeedRecoverable
        };
        let origin = if self.nfc_tap_unused(link, now_ms) {
            // The tap is this operation's presence from here on, whether or not the
            // registration then succeeds: it counts for one credential operation.
            self.use_nfc_tap();
            default_origin
        } else {
            let (name, display_name) = names(&request.user);
            let registration = Registration {
                rp_id: shown_rp.as_str(),
                account: Account {
                    name: name.as_deref(),
                    display_name: display_name.as_deref(),
                    origin: None,
                },
                default_origin,
            };
            match ui.register(registration, USER_ACTION_TIMEOUT_MS) {
                Choice::Chose(origin) => origin,
                Choice::Rejected => return presence(crate::ui::Answer::Rejected),
                Choice::TimedOut => return presence(crate::ui::Answer::TimedOut),
                Choice::Cancelled => return presence(crate::ui::Answer::Cancelled),
            }
        };
        self.consume_token_flags();
        // Steps 21 to 23: the key pair, stored as the origin and discoverability require. A
        // discoverable credential enters the index only once its response is written: until
        // then the one it replaces keeps its entry and key, as the RP has received no other.
        let (created, reservation) = self.create(&keys, request, &rp_id_hash, origin, rk, alg)?;
        let written = self.attest(request, &rp_id_hash, (uv, origin), &created, encoder);
        match (written, reservation) {
            (Ok(()), Some(reservation)) => {
                self.store.commit(reservation, &created.id)?;
            }
            (Ok(()), None) => {}
            (Err(status), Some(reservation)) => {
                self.store.release(reservation);
                return Err(status);
            }
            (Err(status), None) => return Err(status),
        }
        Ok(())
    }

    /// Writes the response for `created` (§6.1.2 step 24): packed self attestation, or none when
    /// the preference puts it first.
    fn attest(
        &mut self,
        request: &MakeCredentialRequest,
        rp_id_hash: &[u8; KEY_LEN],
        (uv, origin): (bool, Origin),
        created: &Created,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let auth_data = authenticator_data(
            rp_id_hash,
            flags(true, uv, origin) | AT,
            Some((&created.id, &created.public_key)),
        )?;
        if request.attestation_none {
            write_full(
                encoder
                    .map(3)
                    .and_then(|encoder| encoder.unsigned(0x01))
                    .and_then(|encoder| encoder.text("none"))
                    .and_then(|encoder| encoder.unsigned(0x02))
                    .and_then(|encoder| encoder.bytes(&auth_data))
                    .and_then(|encoder| encoder.unsigned(0x03))
                    .and_then(|encoder| encoder.map(0)),
            )
        } else {
            let signature = sign_self_attestation(
                &mut self.crypto,
                &created.private_key,
                &auth_data,
                &request.client_data_hash,
            )
            .map_err(|_| StatusCode::Other)?;
            write_full(
                encoder
                    .map(3)
                    .and_then(|encoder| encoder.unsigned(0x01))
                    .and_then(|encoder| encoder.text("packed"))
                    .and_then(|encoder| encoder.unsigned(0x02))
                    .and_then(|encoder| encoder.bytes(&auth_data))
                    .and_then(|encoder| encoder.unsigned(0x03)),
            )?;
            write_full(encode_packed_statement(encoder, &signature))
        }
    }

    /// Generates the key pair of a credential of `origin` and seals its ID (§6.1.2 steps 21 to
    /// 23). A seed-recoverable key derives from the seed and a fresh credential seed; a
    /// device-only key is drawn from the TRNG into a key slot when discoverable, or derived under
    /// the device key `K_dev` when not, so nothing outside NVM reproduces it. A discoverable
    /// credential takes the index slot of the one it replaces for this RP and user (step 22.2),
    /// or a free one; no room is CTAP2_ERR_KEY_STORE_FULL (step 22.4). Its reservation comes
    /// back uncommitted, for the caller to commit or release.
    fn create(
        &mut self,
        keys: &KeyRing,
        request: &MakeCredentialRequest,
        rp_id_hash: &[u8; KEY_LEN],
        origin: Origin,
        rk: bool,
        alg: i64,
    ) -> Result<(Created, Option<Reservation>), StatusCode> {
        let reset_id = self.store.config().reset_id;
        let reservation = if rk {
            let crypto = &self.crypto;
            let user_id = &request.user.id;
            let rp_id = request.rp_id.as_str();
            Some(self.store.reserve(rp_id_hash, rp_id, |entry| {
                credential_id::open(crypto, keys, rp_id, entry.credential_id, reset_id)
                    .is_ok_and(|stored| stored.user.is_some_and(|user| &user.id == user_id))
            })?)
        } else {
            None
        };
        match self.create_reserved(keys, request, origin, alg, reservation.as_ref()) {
            Ok(created) => Ok((created, reservation)),
            Err(status) => {
                if let Some(reservation) = reservation {
                    self.store.release(reservation);
                }
                Err(status)
            }
        }
    }

    /// The key and sealed ID of a new credential, its index slot already reserved when
    /// discoverable.
    fn create_reserved(
        &mut self,
        keys: &KeyRing,
        request: &MakeCredentialRequest,
        origin: Origin,
        alg: i64,
        reservation: Option<&Reservation>,
    ) -> Result<Created, StatusCode> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let (key, private_key) = match (origin, reservation) {
            (Origin::SeedRecoverable, _) => {
                self.crypto.random(&mut seed[..]);
                let private_key = keys
                    .credential_key(&self.crypto, &seed)
                    .map_err(|_| StatusCode::Other)?;
                (KeySource::Seed(*seed), private_key)
            }
            (Origin::DeviceOnly, None) => {
                let device_key = self.store.device_key_or_create(&mut self.crypto);
                self.crypto.random(&mut seed[..]);
                let private_key = DeviceKeys::new(device_key)
                    .credential_key(&self.crypto, &seed)
                    .map_err(|_| StatusCode::Other)?;
                (KeySource::Device(*seed), private_key)
            }
            (Origin::DeviceOnly, Some(reservation)) => {
                let mut private_key = Zeroizing::new([0u8; KEY_LEN]);
                // Drawn until it is a valid scalar, so the key is uniform in 1..n; a draw is
                // rejected with probability below 2^-32.
                loop {
                    self.crypto.random(&mut private_key[..]);
                    if is_p256_private_key(&private_key) {
                        break;
                    }
                }
                let mut cred_random_uv = Zeroizing::new([0u8; KEY_LEN]);
                let mut cred_random = Zeroizing::new([0u8; KEY_LEN]);
                self.crypto.random(&mut cred_random_uv[..]);
                self.crypto.random(&mut cred_random[..]);
                let secrets = DeviceKey {
                    private_key,
                    cred_random_uv,
                    cred_random,
                };
                let key = self
                    .store
                    .store_key(&mut self.crypto, reservation, &secrets)?;
                (key, secrets.private_key)
            }
        };
        let public_key = self
            .crypto
            .p256_public_key(&private_key)
            .map_err(|_| StatusCode::Other)?;
        let user = reservation.map(|_| User {
            id: request.user.id.clone(),
            name: request.user.name.clone(),
            display_name: request.user.display_name.clone(),
        });
        // A discoverable ID carries the store ID, so deleting its entry revokes it (§6.1.3).
        let store = user
            .is_some()
            .then(|| self.store.store_id_or_create(&mut self.crypto));
        let credential = Credential {
            key,
            alg,
            cred_protect: CredProtect::Optional,
            user,
            reset_id: self.store.config().reset_id,
            store,
        };
        let id = credential_id::seal(&mut self.crypto, keys, &request.rp_id, &credential).map_err(
            |error| match error {
                // The user handle was checked before; a key source or store ID that does not fit
                // is a bug.
                SealError::TooLong => StatusCode::InvalidParameter,
                SealError::KeySource | SealError::StoreId => StatusCode::Other,
            },
        )?;
        Ok(Created {
            id,
            public_key,
            private_key,
        })
    }
}

#[cfg(test)]
pub(super) mod tests;

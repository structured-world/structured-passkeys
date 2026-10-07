//! authenticatorCredentialManagement (CTAP 2.2 §6.8): the discoverable credentials of the index,
//! listed, deleted and renamed by a platform that holds a pinUvAuthToken with the `cm`
//! permission.

use alloc::string::String;
use alloc::vec::Vec;

use super::client_pin::{Bytes, write_full};
use super::credential::{PUBLIC_KEY, presence_or_timeout, shown_rp_id};
use super::make_credential::{UserEntity, user_entity};
use super::{Authenticator, NEXT_ASSERTION_TIMEOUT_MS, StatusCode};
use crate::attestation::encode_cose_key;
use crate::cbor::{self, Decoder, Encoder, Key};
use crate::credential_id::{self, Credential, Names};
use crate::crypto::{Crypto, KEY_LEN};
use crate::keys::KeyRing;
use crate::pin::Permissions;
use crate::storage::{EntryId, Storage, StoreError};
use crate::ui::{Account, Prompt, USER_ACTION_TIMEOUT_MS, Ui};

/// authenticatorCredentialManagement subcommands (§6.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubCommand {
    /// getCredsMetadata.
    GetCredsMetadata = 0x01,
    /// enumerateRPsBegin.
    EnumerateRpsBegin = 0x02,
    /// enumerateRPsGetNextRP.
    EnumerateRpsGetNextRp = 0x03,
    /// enumerateCredentialsBegin.
    EnumerateCredentialsBegin = 0x04,
    /// enumerateCredentialsGetNextCredential.
    EnumerateCredentialsGetNextCredential = 0x05,
    /// deleteCredential.
    DeleteCredential = 0x06,
    /// updateUserInformation.
    UpdateUserInformation = 0x07,
}

impl SubCommand {
    const fn from_number(number: u64) -> Option<Self> {
        Some(match number {
            0x01 => SubCommand::GetCredsMetadata,
            0x02 => SubCommand::EnumerateRpsBegin,
            0x03 => SubCommand::EnumerateRpsGetNextRp,
            0x04 => SubCommand::EnumerateCredentialsBegin,
            0x05 => SubCommand::EnumerateCredentialsGetNextCredential,
            0x06 => SubCommand::DeleteCredential,
            0x07 => SubCommand::UpdateUserInformation,
            _ => return None,
        })
    }

    /// The continuations, which carry no pinUvAuthParam and go on from the state their begin
    /// subcommand left.
    const fn continues(self) -> bool {
        matches!(
            self,
            SubCommand::EnumerateRpsGetNextRp | SubCommand::EnumerateCredentialsGetNextCredential
        )
    }
}

/// An authenticatorCredentialManagement request, owning its members. Not `Clone`: its
/// `pinUvAuthParam` wipes itself when the one request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct CredentialManagementRequest {
    sub_command: SubCommand,
    /// `subCommandParams` as received, which the pinUvAuthParam authenticates.
    params: Option<Vec<u8>>,
    rp_id_hash: Option<[u8; KEY_LEN]>,
    credential_id: Option<Vec<u8>>,
    user: Option<UserEntity>,
    protocol: Option<u64>,
    pin_uv_auth_param: Option<Bytes<KEY_LEN>>,
}

impl CredentialManagementRequest {
    /// Whether this request continues an enumeration, which keeps the state it goes on from.
    pub(super) const fn continues(&self) -> bool {
        self.sub_command.continues()
    }
}

/// The members of `subCommandParams` (§6.8).
#[derive(Default)]
struct Params {
    rp_id_hash: Option<[u8; KEY_LEN]>,
    credential_id: Option<Vec<u8>>,
    user: Option<UserEntity>,
}

/// Reads a PublicKeyCredentialDescriptor (WebAuthn L3 §5.8.3) into its `id`; `type` must be a
/// text string, and a credential of another type is none this authenticator holds.
fn descriptor(decoder: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, cbor::Error> {
    decoder.map(|entries| {
        let mut id = None;
        let mut kind = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text("id") => id = Some(value.bytes()?.to_vec()),
                Key::Text("type") => kind = Some(value.text()? == PUBLIC_KEY),
                _ => value.skip()?,
            }
        }
        // Without `type` the descriptor is incomplete; another type names no credential here,
        // which deleteCredential then reports as not found.
        Ok(match (id, kind) {
            (Some(id), Some(true)) => Some(id),
            (Some(_), Some(false)) => Some(Vec::new()),
            _ => None,
        })
    })
}

fn params(raw: &[u8]) -> Result<Params, StatusCode> {
    let mut decoder = Decoder::new(raw);
    let read = decoder.map(|entries| {
        let mut params = Params::default();
        let mut short_hash = false;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => {
                    let hash = value.bytes()?;
                    match hash.try_into() {
                        Ok(hash) => params.rp_id_hash = Some(hash),
                        Err(_) => short_hash = true,
                    }
                }
                Key::Int(0x02) => params.credential_id = descriptor(value)?,
                Key::Int(0x03) => params.user = user_entity(value)?,
                _ => value.skip()?,
            }
        }
        Ok((params, short_hash))
    });
    let (params, short_hash) = read.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    // An RP ID hash is SHA-256, 32 bytes.
    if short_hash {
        return Err(StatusCode::InvalidLength);
    }
    Ok(params)
}

/// Parses the CBOR parameters of authenticatorCredentialManagement (§6.8). Unknown members are
/// ignored (§8); `subCommand` is required, and a subcommand §6.8 does not define is
/// CTAP2_ERR_INVALID_SUBCOMMAND.
pub(super) fn parse(parameters: &[u8]) -> Result<CredentialManagementRequest, StatusCode> {
    let mut decoder = Decoder::new(parameters);
    let read = decoder.map(|entries| {
        let mut sub_command = None;
        let mut raw = None;
        let mut protocol = None;
        let mut pin_uv_auth_param = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => sub_command = Some(value.unsigned()?),
                Key::Int(0x02) => {
                    let item = value.encoded_item()?;
                    // A map, as §6.8 defines it.
                    Decoder::new(item).map(|_| Ok(()))?;
                    raw = Some(item.to_vec());
                }
                Key::Int(0x03) => protocol = Some(value.unsigned()?),
                Key::Int(0x04) => pin_uv_auth_param = Some(Bytes::new(value.bytes()?)),
                _ => value.skip()?,
            }
        }
        Ok((sub_command, raw, protocol, pin_uv_auth_param))
    });
    let (sub_command, raw, protocol, pin_uv_auth_param) = read.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    let sub_command = sub_command.ok_or(StatusCode::MissingParameter)?;
    let sub_command = SubCommand::from_number(sub_command).ok_or(StatusCode::InvalidSubcommand)?;
    let Params {
        rp_id_hash,
        credential_id,
        user,
    } = match &raw {
        Some(raw) => params(raw)?,
        None => Params::default(),
    };
    Ok(CredentialManagementRequest {
        sub_command,
        params: raw,
        rp_id_hash,
        credential_id,
        user,
        protocol,
        pin_uv_auth_param,
    })
}

/// What enumerateRPsGetNextRP and enumerateCredentialsGetNextCredential go on from (§6.8.3,
/// §6.8.4): what is left to return, and the time of the last call. Any other command ends it.
#[derive(Debug)]
pub(super) struct Enumeration {
    kind: Enumerated,
    next: usize,
    last_ms: u64,
}

#[derive(Debug)]
enum Enumerated {
    /// The RP ID hashes, each once, in the order enumerateRPsBegin returned the first.
    Rps(Vec<[u8; KEY_LEN]>),
    /// The credentials of one RP, newest first.
    Credentials {
        rp_id_hash: [u8; KEY_LEN],
        entries: Vec<EntryId>,
    },
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs an authenticatorCredentialManagement request that arrived on `link` (§6.8), writing
    /// its response map, if any, into `encoder`.
    pub(super) fn credential_management<U: Ui>(
        &mut self,
        request: &CredentialManagementRequest,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let now_ms = ui.now_ms();
        if request.sub_command.continues() {
            return self.continue_enumeration(request.sub_command, now_ms, encoder);
        }
        self.authorize(request, now_ms)?;
        let keys = KeyRing::new(&mut self.crypto);
        match request.sub_command {
            SubCommand::GetCredsMetadata => self.creds_metadata(encoder),
            SubCommand::EnumerateRpsBegin => self.enumerate_rps(now_ms, encoder),
            SubCommand::EnumerateCredentialsBegin => {
                let rp_id_hash = request.rp_id_hash.ok_or(StatusCode::MissingParameter)?;
                self.enumerate_credentials(&keys, rp_id_hash, now_ms, encoder)
            }
            SubCommand::DeleteCredential => self.delete_credential(&keys, request, ui),
            SubCommand::UpdateUserInformation => self.update_user(&keys, request),
            SubCommand::EnumerateRpsGetNextRp
            | SubCommand::EnumerateCredentialsGetNextCredential => {
                unreachable!("continuations return above")
            }
        }
    }

    /// The checks every subcommand but the continuations makes (§6.8.2 to §6.8.6, steps 1 to the
    /// permission): a pinUvAuthParam, the subcommand's parameters, a supported protocol, a MAC
    /// under the token over the subcommand and its parameters as received, the `cm`
    /// permission, and the permissions RP ID each subcommand allows. Any failure of the token is
    /// CTAP2_ERR_PIN_AUTH_INVALID. The persistent token (`pcmr`) is not offered
    /// (perCredMgmtRO absent), so only the pinUvAuthToken is tried.
    fn authorize(
        &mut self,
        request: &CredentialManagementRequest,
        now_ms: u64,
    ) -> Result<(), StatusCode> {
        let param = request
            .pin_uv_auth_param
            .as_ref()
            .ok_or(StatusCode::PuatRequired)?;
        let required = match request.sub_command {
            SubCommand::EnumerateCredentialsBegin => request.rp_id_hash.is_some(),
            SubCommand::DeleteCredential => request.credential_id.is_some(),
            SubCommand::UpdateUserInformation => {
                request.credential_id.is_some() && request.user.is_some()
            }
            _ => true,
        };
        if !required {
            return Err(StatusCode::MissingParameter);
        }
        let protocol = Self::param_protocol(request.protocol)?;
        let sub_command = [request.sub_command as u8];
        let message: [&[u8]; 2] = [&sub_command, request.params.as_deref().unwrap_or_default()];
        let verified = self.client_pin.verify_token(
            &self.crypto,
            protocol,
            &message,
            param.get().unwrap_or_default(),
            now_ms,
        );
        if !verified
            || !self
                .client_pin
                .has_permission(Permissions::CREDENTIAL_MANAGEMENT)
        {
            return Err(StatusCode::PinAuthInvalid);
        }
        let rp_allowed = match request.sub_command {
            // These cover every RP: a token bound to one may not.
            SubCommand::GetCredsMetadata | SubCommand::EnumerateRpsBegin => {
                !self.client_pin.has_rp_id()
            }
            SubCommand::EnumerateCredentialsBegin => request
                .rp_id_hash
                .is_some_and(|hash| self.client_pin.permits_rp_id(&hash)),
            // Checked against the credential's RP once it is found.
            _ => true,
        };
        if !rp_allowed {
            return Err(StatusCode::PinAuthInvalid);
        }
        Ok(())
    }

    /// getCredsMetadata (§6.8.2): the discoverable credentials stored, and how many more fit
    /// whatever their key origin.
    fn creds_metadata(&self, encoder: &mut Encoder<'_>) -> Result<(), StatusCode> {
        // At most the index slots, far below u64.
        let existing =
            u64::try_from(self.store.entries().count()).map_err(|_| StatusCode::Other)?;
        let remaining =
            u64::try_from(self.store.remaining_discoverable()).map_err(|_| StatusCode::Other)?;
        write_full(
            encoder
                .map(2)
                .and_then(|encoder| encoder.unsigned(0x01))
                .and_then(|encoder| encoder.unsigned(existing))
                .and_then(|encoder| encoder.unsigned(0x02))
                .and_then(|encoder| encoder.unsigned(remaining)),
        )
    }

    /// The RP ID hashes of the index, each once, in slot order of their first entry.
    fn rp_id_hashes(&self) -> Vec<[u8; KEY_LEN]> {
        let mut hashes: Vec<[u8; KEY_LEN]> = Vec::new();
        for entry in self.store.entries() {
            if !hashes.contains(entry.rp_id_hash) {
                hashes.push(*entry.rp_id_hash);
            }
        }
        hashes
    }

    /// enumerateRPsBegin (§6.8.3): the first RP, the number of RPs, and the state the others are
    /// returned from; CTAP2_ERR_NO_CREDENTIALS with no discoverable credential.
    fn enumerate_rps(&mut self, now_ms: u64, encoder: &mut Encoder<'_>) -> Result<(), StatusCode> {
        let hashes = self.rp_id_hashes();
        let first = *hashes.first().ok_or(StatusCode::NoCredentials)?;
        let total = u64::try_from(hashes.len()).map_err(|_| StatusCode::Other)?;
        self.write_rp(&first, Some(total), encoder)?;
        self.enumeration = Some(Enumeration {
            kind: Enumerated::Rps(hashes),
            next: 1,
            last_ms: now_ms,
        });
        Ok(())
    }

    /// An RP of the enumeration: `rp` with the RP ID the index keeps (the truncated form of
    /// §6.8.7 for a long one, which is why its hash comes too), `rpIDHash`, and `totalRPs` for
    /// the first.
    fn write_rp(
        &self,
        rp_id_hash: &[u8; KEY_LEN],
        total: Option<u64>,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let rp_id = self
            .store
            .newest_first(rp_id_hash)
            .first()
            .map(|entry| String::from(entry.rp_id))
            .ok_or(StatusCode::NoCredentials)?;
        write_full(
            encoder
                .map(2 + usize::from(total.is_some()))
                .and_then(|encoder| encoder.unsigned(0x03))
                .and_then(|encoder| encoder.map(1))
                .and_then(|encoder| encoder.text("id"))
                .and_then(|encoder| encoder.text(&rp_id))
                .and_then(|encoder| encoder.unsigned(0x04))
                .and_then(|encoder| encoder.bytes(rp_id_hash)),
        )?;
        if let Some(total) = total {
            write_full(
                encoder
                    .unsigned(0x05)
                    .and_then(|encoder| encoder.unsigned(total)),
            )?;
        }
        Ok(())
    }

    /// The credential of index entry `entry_id` for the RP `rp_id_hash`, its ID and names as
    /// updated, if the entry still exists and opens.
    pub(super) fn indexed_credential(
        &self,
        keys: &KeyRing,
        rp_id_hash: &[u8; KEY_LEN],
        entry_id: EntryId,
    ) -> Option<(Vec<u8>, Credential)> {
        let entry = self
            .store
            .entry(entry_id.slot)
            .filter(|entry| entry.id == entry_id && entry.rp_id_hash == rp_id_hash)?;
        let reset_id = self.store.config().reset_id;
        let mut credential = credential_id::open_for_hash(
            &self.crypto,
            keys,
            rp_id_hash,
            entry.credential_id,
            reset_id,
        )
        .ok()?;
        self.apply_names(keys, entry_id, entry.credential_id, &mut credential);
        Some((entry.credential_id.to_vec(), credential))
    }

    /// enumerateCredentialsBegin (§6.8.4): the first credential of the RP, newest first, the
    /// number of them, and the state the others are returned from; CTAP2_ERR_NO_CREDENTIALS
    /// when the RP has none.
    fn enumerate_credentials(
        &mut self,
        keys: &KeyRing,
        rp_id_hash: [u8; KEY_LEN],
        now_ms: u64,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let entries: Vec<EntryId> = self
            .store
            .newest_first(&rp_id_hash)
            .iter()
            .map(|entry| entry.id)
            .filter(|&id| self.indexed_credential(keys, &rp_id_hash, id).is_some())
            .collect();
        let first = *entries.first().ok_or(StatusCode::NoCredentials)?;
        let total = u64::try_from(entries.len()).map_err(|_| StatusCode::Other)?;
        self.write_credential(keys, &rp_id_hash, first, Some(total), encoder)?;
        self.enumeration = Some(Enumeration {
            kind: Enumerated::Credentials {
                rp_id_hash,
                entries,
            },
            next: 1,
            last_ms: now_ms,
        });
        Ok(())
    }

    /// A credential of the enumeration (§6.8.4): `user` with every name (the token proved user
    /// verification), `credentialID`, `publicKey`, `totalCredentials` for the first, and
    /// `credProtect`. No largeBlobKey or thirdPartyPayment: neither extension exists here.
    fn write_credential(
        &self,
        keys: &KeyRing,
        rp_id_hash: &[u8; KEY_LEN],
        entry_id: EntryId,
        total: Option<u64>,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let (id, credential) = self
            .indexed_credential(keys, rp_id_hash, entry_id)
            .ok_or(StatusCode::NoCredentials)?;
        let user = credential.user.as_ref().ok_or(StatusCode::Other)?;
        let private_key = self
            .private_key(keys, &credential.key)
            .ok_or(StatusCode::NoCredentials)?;
        let public_key = self
            .crypto
            .p256_public_key(&private_key)
            .map_err(|_| StatusCode::Other)?;
        let user_members =
            1 + usize::from(user.name.is_some()) + usize::from(user.display_name.is_some());
        write_full(
            encoder
                .map(4 + usize::from(total.is_some()))
                .and_then(|encoder| encoder.unsigned(0x06))
                .and_then(|encoder| encoder.map(user_members))
                // Canonical order: "id", "name", "displayName".
                .and_then(|encoder| encoder.text("id"))
                .and_then(|encoder| encoder.bytes(&user.id)),
        )?;
        if let Some(name) = &user.name {
            write_full(encoder.text("name").and_then(|encoder| encoder.text(name)))?;
        }
        if let Some(display_name) = &user.display_name {
            write_full(
                encoder
                    .text("displayName")
                    .and_then(|encoder| encoder.text(display_name)),
            )?;
        }
        write_full(
            encoder
                .unsigned(0x07)
                .and_then(|encoder| encoder.map(2))
                .and_then(|encoder| encoder.text("id"))
                .and_then(|encoder| encoder.bytes(&id))
                .and_then(|encoder| encoder.text("type"))
                .and_then(|encoder| encoder.text(PUBLIC_KEY))
                .and_then(|encoder| encoder.unsigned(0x08)),
        )?;
        write_full(encode_cose_key(encoder, &public_key))?;
        if let Some(total) = total {
            write_full(
                encoder
                    .unsigned(0x09)
                    .and_then(|encoder| encoder.unsigned(total)),
            )?;
        }
        write_full(
            encoder
                .unsigned(0x0A)
                .and_then(|encoder| encoder.unsigned(credential.cred_protect as u64)),
        )
    }

    /// enumerateRPsGetNextRP and enumerateCredentialsGetNextCredential (§6.8.3, §6.8.4): the next
    /// item of the enumeration that the matching begin subcommand started, as stateful commands
    /// do: CTAP2_ERR_NOT_ALLOWED without that state, after its last item, once the token that
    /// authenticated the begin is no longer in use, or more than 30 seconds after the last call.
    fn continue_enumeration(
        &mut self,
        sub_command: SubCommand,
        now_ms: u64,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let Some(mut state) = self.enumeration.take() else {
            return Err(StatusCode::NotAllowed);
        };
        let expired = now_ms
            .checked_sub(state.last_ms)
            .is_none_or(|elapsed| elapsed > NEXT_ASSERTION_TIMEOUT_MS)
            || !self.client_pin.in_use(now_ms);
        if expired {
            return Err(StatusCode::NotAllowed);
        }
        let keys = KeyRing::new(&mut self.crypto);
        match (&state.kind, sub_command) {
            (Enumerated::Rps(hashes), SubCommand::EnumerateRpsGetNextRp) => {
                let hash = *hashes.get(state.next).ok_or(StatusCode::NotAllowed)?;
                self.write_rp(&hash, None, encoder)?;
            }
            (
                Enumerated::Credentials {
                    rp_id_hash,
                    entries,
                },
                SubCommand::EnumerateCredentialsGetNextCredential,
            ) => {
                let entry = *entries.get(state.next).ok_or(StatusCode::NotAllowed)?;
                self.write_credential(&keys, rp_id_hash, entry, None, encoder)?;
            }
            _ => return Err(StatusCode::NotAllowed),
        }
        state.next = state.next.checked_add(1).ok_or(StatusCode::Other)?;
        state.last_ms = now_ms;
        self.enumeration = Some(state);
        Ok(())
    }

    /// The index entry holding the credential ID `id`, with its RP ID hash and the RP ID kept.
    fn entry_with_id(&self, id: &[u8]) -> Option<(EntryId, [u8; KEY_LEN], String)> {
        self.store
            .entries()
            .find(|entry| entry.credential_id == id)
            .map(|entry| (entry.id, *entry.rp_id_hash, String::from(entry.rp_id)))
    }

    /// The entry of `request`'s credential, checked against the token's permissions RP ID
    /// (§6.8.5 and §6.8.6 step 6, then step 7): CTAP2_ERR_NO_CREDENTIALS when no discoverable
    /// credential has that ID.
    fn requested_entry(
        &self,
        request: &CredentialManagementRequest,
    ) -> Result<(EntryId, [u8; KEY_LEN], String), StatusCode> {
        let id = request
            .credential_id
            .as_deref()
            .ok_or(StatusCode::MissingParameter)?;
        let found = self.entry_with_id(id).ok_or(StatusCode::NoCredentials)?;
        if !self.client_pin.permits_rp_id(&found.1) {
            return Err(StatusCode::PinAuthInvalid);
        }
        Ok(found)
    }

    /// deleteCredential (§6.8.5): after the user confirms it on the device, the credential's
    /// entry goes, and with it a device-only key and updated names; its ID no longer opens, a
    /// seed-recoverable one included (§6.1.3, through the store ID).
    fn delete_credential<U: Ui>(
        &mut self,
        keys: &KeyRing,
        request: &CredentialManagementRequest,
        ui: &mut U,
    ) -> Result<(), StatusCode> {
        let (entry, rp_id_hash, rp_id) = self.requested_entry(request)?;
        self.delete_entry(keys, entry, &rp_id_hash, &rp_id, ui)
    }

    /// Deletes the credential of index entry `entry` for the RP `rp_id_hash` (RP ID `rp_id` as
    /// the index keeps it) once the user confirms it on the device: refusal is
    /// CTAP2_ERR_OPERATION_DENIED, no answer CTAP2_ERR_USER_ACTION_TIMEOUT, and an entry that is
    /// gone or no longer opens CTAP2_ERR_NO_CREDENTIALS. The entry goes, and with it a
    /// device-only key and updated names.
    pub(super) fn delete_entry<U: Ui>(
        &mut self,
        keys: &KeyRing,
        entry: EntryId,
        rp_id_hash: &[u8; KEY_LEN],
        rp_id: &str,
        ui: &mut U,
    ) -> Result<(), StatusCode> {
        let (_, credential) = self
            .indexed_credential(keys, rp_id_hash, entry)
            .ok_or(StatusCode::NoCredentials)?;
        let answer = {
            let user = credential.user.as_ref();
            let shown_rp = shown_rp_id(&self.crypto, rp_id);
            ui.confirm(
                Prompt::Delete {
                    rp_id: &shown_rp,
                    account: Account {
                        name: user.and_then(|user| user.name.as_deref()),
                        display_name: user.and_then(|user| user.display_name.as_deref()),
                        origin: Some(credential.key.origin()),
                    },
                },
                USER_ACTION_TIMEOUT_MS,
            )
        };
        presence_or_timeout(answer)?;
        if self.store.remove(entry) {
            Ok(())
        } else {
            Err(StatusCode::NoCredentials)
        }
    }

    /// updateUserInformation (§6.8.6): the credential's name and display name become those of
    /// `user`, an absent or empty one removed (step 11); its user ID must stay (step 10). The
    /// names go into a name override slot, as the credential ID that holds the old ones stays
    /// what the RP knows; CTAP2_ERR_KEY_STORE_FULL when every slot is taken (step 9).
    fn update_user(
        &mut self,
        keys: &KeyRing,
        request: &CredentialManagementRequest,
    ) -> Result<(), StatusCode> {
        let (entry, rp_id_hash, _) = self.requested_entry(request)?;
        let user = request.user.as_ref().ok_or(StatusCode::MissingParameter)?;
        let (id, credential) = self
            .indexed_credential(keys, &rp_id_hash, entry)
            .ok_or(StatusCode::NoCredentials)?;
        if credential.user.as_ref().map(|stored| &stored.id) != Some(&user.id) {
            return Err(StatusCode::InvalidParameter);
        }
        let names = Names {
            name: user.name.clone(),
            display_name: user.display_name.clone(),
        };
        let sealed = credential_id::seal_names(&mut self.crypto, keys, &id, &names);
        self.store
            .set_names(entry, &sealed)
            .map_err(|error| match error {
                StoreError::Full => StatusCode::KeyStoreFull,
                StoreError::TooLong | StoreError::Exhausted | StoreError::Stale => {
                    StatusCode::Other
                }
            })
    }
}

#[cfg(test)]
mod tests;

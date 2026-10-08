//! authenticatorGetAssertion (CTAP 2.2 §6.2) and authenticatorGetNextAssertion (§6.3): parsing a
//! request, the algorithm of §6.2.2, and the state the second command continues from.

use alloc::string::String;
use alloc::vec::Vec;

use super::client_pin::{Bytes, write_full};
use super::credential::{
    Options, PUBLIC_KEY, authenticator_data, descriptors, flags, options, presence, shown,
    shown_rp_id,
};
use super::extensions::{
    HmacSecretInput, HmacSecretOutput, Outputs, Salts, get_assertion_extensions,
};
use super::{Authenticator, Link, StatusCode};
use crate::cbor::{Decoder, Encoder, Full, Key};
use crate::credential_id::{self, CredProtect, Credential, MAX_NAME_LEN};
use crate::crypto::{Crypto, KEY_LEN};
use crate::keys::{CredRandom, KeyRing};
use crate::pin::Permissions;
use crate::storage::{EntryId, Storage};
use crate::ui::{Account, Accounts, Choice, Prompt, USER_ACTION_TIMEOUT_MS, Ui};

/// How long authenticatorGetNextAssertion continues an assertion: 30 seconds since the last call
/// to either command (§6.3 step 3).
pub const NEXT_ASSERTION_TIMEOUT_MS: u64 = 30_000;

/// An authenticatorGetAssertion request, owning its members. Not `Clone`: its `pinUvAuthParam`
/// wipes itself when the one request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct GetAssertionRequest {
    rp_id: String,
    client_data_hash: [u8; KEY_LEN],
    allow_list: Option<Vec<Vec<u8>>>,
    /// The hmac-secret extension input; any other extension is ignored (§6.2.2 step 12.1).
    hmac_secret: Option<HmacSecretInput>,
    options: Options,
    pin_uv_auth_param: Option<Bytes<KEY_LEN>>,
    pin_uv_auth_protocol: Option<u64>,
}

/// Parses the CBOR parameters of authenticatorGetAssertion (§6.2). Unknown members are ignored
/// (§8); rpId and clientDataHash are required.
pub(super) fn parse(parameters: &[u8]) -> Result<GetAssertionRequest, StatusCode> {
    let mut decoder = Decoder::new(parameters);
    let mut missing = false;
    let parsed = decoder.map(|entries| {
        let mut rp_id = None;
        let mut client_data_hash = None;
        let mut allow_list = None;
        let mut hmac_secret = None;
        let mut request_options = Options::default();
        let mut pin_uv_auth_param = None;
        let mut pin_uv_auth_protocol = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => rp_id = Some(value.text()?),
                Key::Int(0x02) => client_data_hash = Some(value.bytes()?),
                Key::Int(0x03) => allow_list = Some(descriptors(value, &mut missing)?),
                Key::Int(0x04) => hmac_secret = get_assertion_extensions(value, &mut missing)?,
                Key::Int(0x05) => request_options = options(value)?,
                Key::Int(0x06) => pin_uv_auth_param = Some(Bytes::new(value.bytes()?)),
                Key::Int(0x07) => pin_uv_auth_protocol = Some(value.unsigned()?),
                _ => value.skip()?,
            }
        }
        Ok((
            rp_id,
            client_data_hash,
            allow_list,
            hmac_secret,
            request_options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        ))
    });
    let (
        rp_id,
        client_data_hash,
        allow_list,
        hmac_secret,
        request_options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    ) = parsed.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    let (Some(rp_id), Some(client_data_hash)) = (rp_id, client_data_hash) else {
        return Err(StatusCode::MissingParameter);
    };
    if missing {
        return Err(StatusCode::MissingParameter);
    }
    // WebAuthn L3 §5.8.1: the hash of the client data is SHA-256, 32 bytes.
    let client_data_hash = client_data_hash
        .try_into()
        .map_err(|_| StatusCode::InvalidLength)?;
    Ok(GetAssertionRequest {
        rp_id: String::from(rp_id),
        client_data_hash,
        // §6.2: a present allowList limits the assertion to the credentials it denotes, and the
        // discoverable credentials of §6.2.2 are searched only when it is absent; an empty one
        // denotes none, which a platform never sends (§6.2 has it omitted instead).
        allow_list,
        hmac_secret,
        options: request_options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

/// What authenticatorGetNextAssertion continues from (§6.2.2 step 15.2.2): the parameters of the
/// assertion, the discoverable credentials still to return, by their index entry, and the time
/// of the last call.
#[derive(Debug)]
pub(super) struct NextAssertions {
    rp_id: String,
    rp_id_hash: [u8; KEY_LEN],
    client_data_hash: [u8; KEY_LEN],
    /// Every applicable credential, most recently created first; the first was returned.
    entries: Vec<EntryId>,
    /// `credentialCounter`: the index of the next one to return.
    next: usize,
    last_ms: u64,
    up: bool,
    uv: bool,
    /// Whether a pinUvAuthToken authenticated the assertion, whose expiry ends the state.
    token: bool,
    /// The hmac-secret salts, which every credential returned answers as the first did.
    salts: Option<Salts>,
}

/// A credential that may answer the assertion, by where it is found. It is decoded again each
/// time it is shown or signs with, so the device's small heap holds one decoded credential at a
/// time however many the RP has.
#[derive(Clone, Copy, Debug)]
enum Candidate {
    /// The allowList member at this position.
    Listed(usize),
    /// The discoverable credential of this index entry.
    Indexed(EntryId),
}

/// The credential that signs, with its ID.
struct Chosen {
    id: Vec<u8>,
    credential: Credential,
}

/// The accounts of the candidates for the account picker, each decoded when the screen shows it.
struct Offered<'a, C: Crypto, S: Storage> {
    authenticator: &'a Authenticator<C, S>,
    keys: &'a KeyRing,
    request: &'a GetAssertionRequest,
    candidates: &'a [Candidate],
}

impl<C: Crypto, S: Storage> Accounts for Offered<'_, C, S> {
    fn count(&self) -> usize {
        self.candidates.len()
    }

    fn read<R>(&mut self, index: usize, show: impl FnOnce(Account<'_>) -> R) -> Option<R> {
        let (_, credential) = self.authenticator.read_candidate(
            self.keys,
            self.request,
            *self.candidates.get(index)?,
        )?;
        let (name, display_name) = account_names(&credential);
        Some(show(Account {
            name: name.as_deref(),
            display_name: display_name.as_deref(),
            origin: Some(credential.key.origin()),
        }))
    }
}

/// The names a screen shows for `credential`: those of a discoverable one, made safe.
fn account_names(credential: &Credential) -> (Option<String>, Option<String>) {
    credential.user.as_ref().map_or((None, None), |user| {
        (
            user.name.as_deref().map(|name| shown(name, MAX_NAME_LEN)),
            user.display_name
                .as_deref()
                .map(|name| shown(name, MAX_NAME_LEN)),
        )
    })
}

/// The members of an assertion response besides the signed parts, and the hmac-secret salts its
/// authenticator data answers.
struct Extras<'a> {
    number_of_credentials: Option<usize>,
    user_selected: bool,
    salts: Option<&'a Salts>,
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs an authenticatorGetAssertion request that arrived on `link` (§6.2.2), writing its
    /// response map into `encoder`.
    pub(super) fn get_assertion<U: Ui>(
        &mut self,
        request: &GetAssertionRequest,
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
        // Step 5: pinUvAuthParam takes precedence over the uv option; a platform never sends rk.
        let mut uv_option = protocol.is_none() && request.options.uv == Some(true);
        if request.options.rk.is_some() {
            return Err(StatusCode::UnsupportedOption);
        }
        let up = request.options.up.unwrap_or(true);
        // §12.7: hmac-secret needs user presence.
        if request.hmac_secret.is_some() && !up {
            return Err(StatusCode::UnsupportedOption);
        }
        // Step 6: under alwaysUv a ceremony with user presence gets built-in user verification
        // when the request brings no other.
        if self.store.config().always_uv && up && protocol.is_none() {
            uv_option = true;
        }
        let rp_id_hash = self.crypto.sha256(&[request.rp_id.as_bytes()]);
        // Step 7: user verification.
        let uv = if let (Some(protocol), Some(param)) = (protocol, &request.pin_uv_auth_param) {
            self.verify_param(
                protocol,
                param.get().unwrap_or_default(),
                &request.client_data_hash,
                Permissions::GET_ASSERTION,
                &rp_id_hash,
                now_ms,
            )?;
            true
        } else if uv_option {
            self.built_in_uv(ui)?;
            true
        } else {
            false
        };
        // Step 9: the applicable credentials.
        let keys = KeyRing::new(&mut self.crypto);
        let applicable = self.applicable(&keys, request, &rp_id_hash, uv);
        let Some(&first) = applicable.first() else {
            return Err(StatusCode::NoCredentials);
        };
        let shown_rp = shown_rp_id(&self.crypto, &request.rp_id);
        // A live tap means the device rests on the phone: no screen is answered then, whether or
        // not the request asks for presence, which only then the tap supplies and uses up.
        let tapped = self.nfc_tap_unused(link, now_ms);
        let on_tap = up && tapped;
        let several = request.allow_list.is_none() && applicable.len() > 1;
        // Step 15.2.3: a display lists the accounts when the request asks for presence or
        // verification. Over the tap the platform gets the count and goes on with
        // getNextAssertion, as without a display. A request with neither asks for no screen at
        // all: up=false is the platform's pre-flight of an allowList or excludeList (§6.2, note
        // on "up"), and its assertion without UP is not valid at the WebAuthn layer, so a screen
        // would interrupt every pre-flight and give the user nothing to decide.
        let pick = several && !tapped && (up || uv);
        let mut selected = 0;
        let mut number_of_credentials = None;
        let mut user_selected = false;
        if pick {
            let mut offered = Offered {
                authenticator: self,
                keys: &keys,
                request,
                candidates: &applicable,
            };
            selected = match ui.pick(shown_rp.as_str(), &mut offered, USER_ACTION_TIMEOUT_MS) {
                // An index the screen could not have offered is a bug of the screen; refusing
                // it signs nothing.
                Choice::Chose(index) if index < applicable.len() => index,
                Choice::Chose(_) => return Err(StatusCode::Other),
                Choice::Rejected | Choice::TimedOut => return Err(StatusCode::OperationDenied),
                Choice::Cancelled => return Err(StatusCode::KeepaliveCancel),
            };
            user_selected = true;
        } else if up && !on_tap {
            // Step 11: user presence on the device, for the credential that will sign.
            let mut offered = Offered {
                authenticator: self,
                keys: &keys,
                request,
                candidates: &[first],
            };
            let answer = offered
                .read(0, |account| {
                    ui.confirm(
                        Prompt::Assertion {
                            rp_id: shown_rp.as_str(),
                            account,
                        },
                        USER_ACTION_TIMEOUT_MS,
                    )
                })
                .ok_or(StatusCode::NoCredentials)?;
            presence(answer)?;
        }
        if up {
            self.consume_token_flags();
        }
        // The tap is this assertion's presence from here on, whether or not the signature is
        // then written: it counts for one credential operation.
        if on_tap {
            self.use_nfc_tap();
        }
        // §12.7: the salts are read after consent and user verification.
        let salts = request
            .hmac_secret
            .as_ref()
            .map(|input| self.salts(input))
            .transpose()?;
        // Step 15.2.2: the platform gets the count and the rest with getNextAssertion, which
        // continues only once this response has been written (§6.3 follows a received assertion).
        let continuation = (several && !pick).then(|| NextAssertions {
            rp_id: request.rp_id.clone(),
            rp_id_hash,
            client_data_hash: request.client_data_hash,
            entries: applicable
                .iter()
                .filter_map(|candidate| match candidate {
                    Candidate::Indexed(entry) => Some(*entry),
                    Candidate::Listed(_) => None,
                })
                .collect(),
            next: 1,
            last_ms: ui.now_ms(),
            up,
            uv,
            token: protocol.is_some(),
            salts: None,
        });
        if continuation.is_some() {
            number_of_credentials = Some(applicable.len());
        }
        let chosen = self
            .read_candidate(&keys, request, applicable[selected])
            .map(|(id, credential)| Chosen {
                id: id.to_vec(),
                credential,
            })
            .ok_or(StatusCode::NoCredentials)?;
        drop(applicable);
        let extras = Extras {
            number_of_credentials,
            user_selected,
            salts: salts.as_ref(),
        };
        self.assert(
            &keys,
            &chosen,
            &rp_id_hash,
            &request.client_data_hash,
            (up, uv),
            &extras,
            encoder,
        )?;
        self.next_assertions = continuation.map(|state| NextAssertions { salts, ..state });
        Ok(())
    }

    /// The credentials an assertion may use (§6.2.2 step 9): those of the allowList this
    /// authenticator created for the RP, or else the discoverable ones for it, most recently
    /// created first; without user verification, credProtect removes level 3 ones, and level 2
    /// ones when no allowList names them.
    fn applicable(
        &self,
        keys: &KeyRing,
        request: &GetAssertionRequest,
        rp_id_hash: &[u8; KEY_LEN],
        uv: bool,
    ) -> Vec<Candidate> {
        let listed = request.allow_list.is_some();
        let mut candidates: Vec<_> = match &request.allow_list {
            Some(allow_list) => (0..allow_list.len()).map(Candidate::Listed).collect(),
            None => self
                .store
                .newest_first(rp_id_hash)
                .iter()
                .map(|entry| Candidate::Indexed(entry.id))
                .collect(),
        };
        candidates.retain(|&candidate| {
            self.read_candidate(keys, request, candidate)
                .is_some_and(|(_, credential)| {
                    let protected = match credential.cred_protect {
                        CredProtect::Required => uv,
                        CredProtect::OptionalWithCredentialIdList => uv || listed,
                        CredProtect::Optional => true,
                    };
                    // An allowList credential was located with its key; an index entry's key
                    // must still be live.
                    protected && (listed || self.private_key(keys, &credential.key).is_some())
                })
        });
        candidates
    }

    /// Decodes `candidate` of `request`: its credential ID and the credential, if it is still
    /// this authenticator's for the RP.
    fn read_candidate<'a>(
        &'a self,
        keys: &KeyRing,
        request: &'a GetAssertionRequest,
        candidate: Candidate,
    ) -> Option<(&'a [u8], Credential)> {
        match candidate {
            Candidate::Listed(position) => {
                let id = request.allow_list.as_ref()?.get(position)?;
                Some((id, self.locate(keys, &request.rp_id, id)?))
            }
            Candidate::Indexed(entry_id) => self.read_entry(keys, &request.rp_id, entry_id),
        }
    }

    /// Decodes the discoverable credential of index entry `entry_id` for `rp_id`, if the entry
    /// still exists. An entry in the index is the current credential for its user, so no
    /// overwrite check applies.
    fn read_entry(
        &self,
        keys: &KeyRing,
        rp_id: &str,
        entry_id: EntryId,
    ) -> Option<(&[u8], Credential)> {
        let entry = self
            .store
            .entry(entry_id.slot)
            .filter(|entry| entry.id == entry_id)?;
        let reset_id = self.store.config().reset_id;
        let mut credential =
            credential_id::open(&self.crypto, keys, rp_id, entry.credential_id, reset_id).ok()?;
        self.apply_names(keys, entry_id, entry.credential_id, &mut credential);
        Some((entry.credential_id, credential))
    }

    /// Signs the assertion with `chosen` and writes the response (§6.2.2 steps 15.3 and 16): the
    /// user member for a discoverable credential, its names only when the ceremony verified the
    /// user, and the hmac-secret output under the CredRandom of the response's UV flag (§12.7).
    #[expect(
        clippy::too_many_arguments,
        reason = "the signed parts of one assertion, borrowed from the command that runs it"
    )]
    fn assert(
        &mut self,
        keys: &KeyRing,
        chosen: &Chosen,
        rp_id_hash: &[u8; KEY_LEN],
        client_data_hash: &[u8; KEY_LEN],
        (up, uv): (bool, bool),
        extras: &Extras<'_>,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let origin = chosen.credential.key.origin();
        // §12.7: a credential without its CredRandom gets no output; one located with its key
        // always has it.
        let hmac_secret = match extras.salts {
            Some(salts) => self
                .cred_random(keys, &chosen.credential.key, CredRandom::for_uv(uv))
                .map(|cred_random| self.hmac_secret_output(salts, &cred_random))
                .transpose()?
                .map(HmacSecretOutput::Secret),
            None => None,
        };
        let outputs = Outputs {
            hmac_secret,
            ..Outputs::default()
        };
        let auth_data = authenticator_data(rp_id_hash, flags(up, uv, origin), None, &outputs)?;
        let private_key = self
            .private_key(keys, &chosen.credential.key)
            .ok_or(StatusCode::NoCredentials)?;
        let digest = self.crypto.sha256(&[&auth_data, client_data_hash]);
        let signature = self
            .crypto
            .p256_sign(&private_key, &digest)
            .map_err(|_| StatusCode::Other)?;
        let user = chosen.credential.user.as_ref();
        let entries = 3
            + usize::from(user.is_some())
            + usize::from(extras.number_of_credentials.is_some())
            + usize::from(extras.user_selected);
        write_full(write_response(
            encoder,
            entries,
            &chosen.id,
            &auth_data,
            signature.as_der(),
        ))?;
        if let Some(user) = user {
            let name = user.name.as_deref().filter(|_| uv);
            let display_name = user.display_name.as_deref().filter(|_| uv);
            let members = 1 + usize::from(name.is_some()) + usize::from(display_name.is_some());
            write_full(
                encoder
                    .unsigned(0x04)
                    .and_then(|encoder| encoder.map(members)),
            )?;
            // Canonical order: "id", "name", "displayName".
            write_full(
                encoder
                    .text("id")
                    .and_then(|encoder| encoder.bytes(&user.id)),
            )?;
            if let Some(name) = name {
                write_full(encoder.text("name").and_then(|encoder| encoder.text(name)))?;
            }
            if let Some(display_name) = display_name {
                write_full(
                    encoder
                        .text("displayName")
                        .and_then(|encoder| encoder.text(display_name)),
                )?;
            }
        }
        if let Some(count) = extras.number_of_credentials {
            // At most the index slots, far below u64.
            let count = u64::try_from(count).map_err(|_| StatusCode::Other)?;
            write_full(
                encoder
                    .unsigned(0x05)
                    .and_then(|encoder| encoder.unsigned(count)),
            )?;
        }
        if extras.user_selected {
            write_full(
                encoder
                    .unsigned(0x06)
                    .and_then(|encoder| encoder.bool(true)),
            )?;
        }
        Ok(())
    }

    /// authenticatorGetNextAssertion (§6.3): the next credential of the assertion the last
    /// command started, within 30 seconds of the last call; anything else is
    /// CTAP2_ERR_NOT_ALLOWED.
    pub(super) fn get_next_assertion<U: Ui>(
        &mut self,
        ui: &mut U,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), StatusCode> {
        let now_ms = ui.now_ms();
        let Some(state) = self.next_assertions.take() else {
            return Err(StatusCode::NotAllowed);
        };
        let Some(&entry_id) = state.entries.get(state.next) else {
            return Err(StatusCode::NotAllowed);
        };
        let expired = now_ms
            .checked_sub(state.last_ms)
            .is_none_or(|elapsed| elapsed > NEXT_ASSERTION_TIMEOUT_MS);
        // §6 "stateful commands": the state MUST be discarded once the pinUvAuthToken that
        // authenticated the initializing command expires, as this command verifies none.
        if expired || (state.token && !self.client_pin.in_use(now_ms)) {
            return Err(StatusCode::NotAllowed);
        }
        let keys = KeyRing::new(&mut self.crypto);
        // A credential deleted since the assertion began has nothing to sign with.
        let chosen = self
            .read_entry(&keys, &state.rp_id, entry_id)
            .map(|(id, credential)| Chosen {
                id: id.to_vec(),
                credential,
            })
            .ok_or(StatusCode::NoCredentials)?;
        let extras = Extras {
            number_of_credentials: None,
            user_selected: false,
            salts: state.salts.as_ref(),
        };
        self.assert(
            &keys,
            &chosen,
            &state.rp_id_hash,
            &state.client_data_hash,
            (state.up, state.uv),
            &extras,
            encoder,
        )?;
        // Steps 7 and 8: the timer restarts and the counter moves on.
        self.next_assertions = Some(NextAssertions {
            next: state
                .next
                .checked_add(1)
                .expect("the counter indexed `entries` above, so it is below a Vec length"),
            last_ms: now_ms,
            ..state
        });
        Ok(())
    }
}

/// Writes the response map header and its first three members: the credential descriptor
/// (`id` before `type`, canonical order), the authenticator data and the signature.
fn write_response(
    encoder: &mut Encoder<'_>,
    entries: usize,
    id: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> Result<(), Full> {
    encoder
        .map(entries)?
        .unsigned(0x01)?
        .map(2)?
        .text("id")?
        .bytes(id)?
        .text("type")?
        .text(PUBLIC_KEY)?
        .unsigned(0x02)?
        .bytes(auth_data)?
        .unsigned(0x03)?
        .bytes(signature)?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;

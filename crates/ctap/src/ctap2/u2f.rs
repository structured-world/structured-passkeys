//! CTAP1/U2F registration and authentication (FIDO U2F Raw Message Formats v1.2) on the key model
//! of the CTAP2 credentials: a U2F key handle is a credential ID, and the application parameter is
//! the RP ID hash its AAD binds, so a credential registered over U2F also answers CTAP2 with the
//! `appid` extension, and a non-discoverable CTAP2 credential answers U2F.

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use super::Authenticator;
use super::credential::shown;
use crate::attestation::{ES256, u2f_certificate};
use crate::credential_id::{self, CredProtect, Credential, KeySource, MAX_NAME_LEN, SEED_LEN};
use crate::crypto::Crypto;
use crate::ctap1::{APPLICATION_LEN, CHALLENGE_LEN, Control, Request, StatusWord, VERSION};
use crate::keys::KeyRing;
use crate::storage::Storage;
use crate::ui::{Account, Answer, Prompt, USER_ACTION_TIMEOUT_MS, Ui};

/// The byte a registration response starts with, "reserved for legacy reasons" (U2F raw messages
/// §4.3).
const REGISTRATION_RESERVED: u8 = 0x05;
/// The byte the signed data of a registration starts with, reserved for future use (§4.3).
const REGISTRATION_SIGNED_RESERVED: u8 = 0x00;
/// The user presence byte of an authentication (§5.4): presence verified. Every signature here
/// is confirmed on the device.
const USER_PRESENT: u8 = 0x01;
/// The counter of an authentication (§5.4): always 0, as for CTAP2 credentials (key model,
/// signature counter).
const COUNTER: [u8; 4] = [0; 4];

/// The application parameter of the registration Chromium sends to a U2F device that holds none
/// of the credentials of an authentication, so the user touches the device and the browser can
/// report that it is not registered: 32 bytes of 0x41, the hash of no real application.
const PROBE_APPLICATION: [u8; APPLICATION_LEN] = [0x41; APPLICATION_LEN];
/// The challenge parameter of that registration, 32 bytes of 0x42.
const PROBE_CHALLENGE: [u8; CHALLENGE_LEN] = [0x42; CHALLENGE_LEN];

/// The bytes of the fingerprint a U2F screen shows, as many as an RP ID's fingerprint.
const FINGERPRINT_BYTES: usize = 8;

/// What a U2F screen shows for the application parameter `application`: a U2F message carries no
/// RP ID, only its hash (§4.1), so the screen names it by "U2F site #" and the first 8 bytes of
/// the hash in upper-case hex, the fingerprint long RP IDs get. A relying party that wants to look
/// like another needs a second preimage of 64 bits.
pub(super) fn u2f_label(application: &[u8; APPLICATION_LEN]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut label = String::from("U2F site #");
    for byte in &application[..FINGERPRINT_BYTES] {
        label.push(char::from(DIGITS[usize::from(byte >> 4)]));
        label.push(char::from(DIGITS[usize::from(byte & 0xF)]));
    }
    label
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs a CTAP1/U2F request that arrived over `CTAPHID_MSG`, asking `ui` for user presence,
    /// and writes the response (the data, then the status word) into `response`, returning its
    /// length. A response that does not fit is replaced by its status word alone, or by the
    /// "no precise diagnosis" status when even that does not fit; an empty `response` gets
    /// nothing. Like any other command, it ends what authenticatorGetNextAssertion and the
    /// credential management enumerations would continue.
    pub fn execute_ctap1<U: Ui>(
        &mut self,
        request: Result<Request, StatusWord>,
        ui: &mut U,
        response: &mut [u8],
    ) -> usize {
        self.next_assertions = None;
        self.enumeration = None;
        let mut data = Vec::new();
        // CTAP 2.2 §7.2.2: with alwaysUv every ceremony verifies the user, which U2F cannot, so
        // U2F is disabled, every message refused before anything about it is reported; getInfo
        // then leaves U2F_V2 out.
        let outcome = if self.store.config().always_uv {
            Err(StatusWord::CommandNotAllowed)
        } else {
            request.and_then(|request| self.run_ctap1(request, ui, &mut data))
        };
        let status = match outcome {
            Ok(()) => StatusWord::NoError,
            Err(status) => {
                data.clear();
                status
            }
        };
        let total = data
            .len()
            .checked_add(2)
            .expect("a response is far below usize");
        let Some(room) = response.get_mut(..total) else {
            return match response.get_mut(..2) {
                Some(room) => {
                    room.copy_from_slice(&StatusWord::Unknown.to_bytes());
                    2
                }
                None => 0,
            };
        };
        let (body, status_word) = room.split_at_mut(data.len());
        body.copy_from_slice(&data);
        status_word.copy_from_slice(&status.to_bytes());
        total
    }

    fn run_ctap1<U: Ui>(
        &mut self,
        request: Request,
        ui: &mut U,
        data: &mut Vec<u8>,
    ) -> Result<(), StatusWord> {
        match request {
            Request::Version => {
                data.extend_from_slice(VERSION);
                Ok(())
            }
            Request::Register {
                challenge,
                application,
            } => self.u2f_register(&challenge, &application, ui, data),
            Request::Authenticate {
                control,
                challenge,
                application,
                key_handle,
            } => self.u2f_authenticate(control, &challenge, &application, &key_handle, ui, data),
        }
    }

    /// U2F_REGISTER (§4): after test-of-user-presence on the device, a new seed-recoverable,
    /// non-discoverable credential for the application, the only origin a U2F credential takes
    /// (no screen offers a choice). The response is §4.3's: the public key, the key handle, the
    /// self-signed certificate of the credential's key, and the signature of that key over the
    /// registration data.
    fn u2f_register<U: Ui>(
        &mut self,
        challenge: &[u8; CHALLENGE_LEN],
        application: &[u8; APPLICATION_LEN],
        ui: &mut U,
        data: &mut Vec<u8>,
    ) -> Result<(), StatusWord> {
        // The probe registration needs no screen: it names no site, and the answer that the user
        // is not present ends it.
        if application == &PROBE_APPLICATION && challenge == &PROBE_CHALLENGE {
            return Err(StatusWord::ConditionsNotSatisfied);
        }
        let label = u2f_label(application);
        // §4.3: SW_CONDITIONS_NOT_SATISFIED until test-of-user-presence; a refusal, a timeout or a
        // cancelled request leaves the user not present.
        if ui.confirm(
            Prompt::U2fRegistration {
                rp_id: label.as_str(),
            },
            USER_ACTION_TIMEOUT_MS,
        ) != Answer::Confirmed
        {
            return Err(StatusWord::ConditionsNotSatisfied);
        }
        let keys = KeyRing::new(&mut self.crypto);
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        self.crypto.random(&mut seed[..]);
        let private_key = keys
            .credential_key(&self.crypto, &seed)
            .map_err(|_| StatusWord::Unknown)?;
        let public_key = self
            .crypto
            .p256_public_key(&private_key)
            .map_err(|_| StatusWord::Unknown)?;
        let credential = Credential {
            key: KeySource::Seed(*seed),
            alg: ES256,
            // §12.1: level 1, the default; U2F has no request member for it.
            cred_protect: CredProtect::Optional,
            user: None,
            reset_id: self.store.config().reset_id,
            store: None,
        };
        let key_handle =
            credential_id::seal_for_hash(&mut self.crypto, &keys, application, &credential)
                .map_err(|_| StatusWord::Unknown)?;
        // §4.3: the key handle length is one byte; a non-discoverable ID is far shorter.
        let key_handle_len = u8::try_from(key_handle.len()).map_err(|_| StatusWord::Unknown)?;
        let certificate = u2f_certificate(&mut self.crypto, &private_key, &public_key)
            .map_err(|_| StatusWord::Unknown)?;
        let digest = self.crypto.sha256(&[
            &[REGISTRATION_SIGNED_RESERVED],
            application,
            challenge,
            &key_handle,
            &public_key,
        ]);
        let signature = self
            .crypto
            .p256_sign(&private_key, &digest)
            .map_err(|_| StatusWord::Unknown)?;
        data.push(REGISTRATION_RESERVED);
        data.extend_from_slice(&public_key);
        data.push(key_handle_len);
        data.extend_from_slice(&key_handle);
        data.extend_from_slice(&certificate);
        data.extend_from_slice(signature.as_der());
        Ok(())
    }

    /// U2F_AUTHENTICATE (§5): the key handle must be a credential ID this authenticator created
    /// for the application and that still lives, else SW_WRONG_DATA (§5.1); a credential of
    /// credProtect level 3 is never used without user verification (CTAP 2.2 §12.1), which U2F
    /// cannot give, so it counts as not this authenticator's. A check-only request ends with
    /// SW_CONDITIONS_NOT_SATISFIED for a valid key handle (§5.1). Any other control byte signs
    /// after the user confirms the sign-in on the device, "don't-enforce" included: every
    /// signature of this authenticator is confirmed where the user sees the site.
    fn u2f_authenticate<U: Ui>(
        &mut self,
        control: Control,
        challenge: &[u8; CHALLENGE_LEN],
        application: &[u8; APPLICATION_LEN],
        key_handle: &[u8],
        ui: &mut U,
        data: &mut Vec<u8>,
    ) -> Result<(), StatusWord> {
        let keys = KeyRing::new(&mut self.crypto);
        let credential = self
            .locate_for_hash(&keys, application, key_handle)
            .filter(|credential| credential.cred_protect != CredProtect::Required)
            .ok_or(StatusWord::WrongData)?;
        if control == Control::CheckOnly {
            return Err(StatusWord::ConditionsNotSatisfied);
        }
        let label = u2f_label(application);
        let (name, display_name) = credential.user.as_ref().map_or((None, None), |user| {
            (
                user.name.as_deref().map(|name| shown(name, MAX_NAME_LEN)),
                user.display_name
                    .as_deref()
                    .map(|name| shown(name, MAX_NAME_LEN)),
            )
        });
        let account = Account {
            name: name.as_deref(),
            display_name: display_name.as_deref(),
            origin: Some(credential.key.origin()),
        };
        if ui.confirm(
            Prompt::Assertion {
                rp_id: label.as_str(),
                account,
            },
            USER_ACTION_TIMEOUT_MS,
        ) != Answer::Confirmed
        {
            return Err(StatusWord::ConditionsNotSatisfied);
        }
        let private_key = self
            .private_key(&keys, &credential.key)
            .ok_or(StatusWord::Unknown)?;
        let digest = self
            .crypto
            .sha256(&[application, &[USER_PRESENT], &COUNTER, challenge]);
        let signature = self
            .crypto
            .p256_sign(&private_key, &digest)
            .map_err(|_| StatusWord::Unknown)?;
        data.push(USER_PRESENT);
        data.extend_from_slice(&COUNTER);
        data.extend_from_slice(signature.as_der());
        Ok(())
    }
}

#[cfg(test)]
mod tests;

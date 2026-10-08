//! The extensions of CTAP 2.2 §12 this authenticator implements: credProtect (§12.1),
//! hmac-secret (§12.7) and hmac-secret-mc (§12.8). Their request inputs, the salts of hmac-secret
//! under the PIN/UV auth protocols, and the extension outputs of the authenticator data.

use alloc::vec::Vec;
use zeroize::Zeroizing;

use super::client_pin::{PeerKey, decapsulate, peer_key};
use super::{Authenticator, StatusCode};
use crate::cbor::{self, Decoder, Encoder, Full, Key};
use crate::credential_id::CredProtect;
use crate::crypto::{AES_BLOCK_LEN, Crypto, KEY_LEN};
use crate::pin::{Protocol, SharedSecret};
use crate::storage::Storage;

/// The extensions getInfo lists (§6.4 `extensions`), in the order of the extension outputs.
pub const NAMES: [&str; 3] = [CRED_PROTECT, HMAC_SECRET, HMAC_SECRET_MC];

const CRED_PROTECT: &str = "credProtect";
const HMAC_SECRET: &str = "hmac-secret";
const HMAC_SECRET_MC: &str = "hmac-secret-mc";

/// Longest salts: salt1 and salt2, 32 bytes each (§12.7).
const MAX_SALTS_LEN: usize = 2 * KEY_LEN;
/// Longest encrypted hmac-secret output: two outputs after protocol two's IV.
const MAX_OUTPUT_LEN: usize = AES_BLOCK_LEN + MAX_SALTS_LEN;
/// Longest encoded extension outputs: a map of three, the two hmac-secret outputs as byte strings
/// of at most [`MAX_OUTPUT_LEN`] bytes, each under its name.
const MAX_OUTPUTS_LEN: usize = 256;

/// The hmac-secret input of getAssertion, also the hmac-secret-mc input of makeCredential
/// (§12.7, §12.8): the platform key agreement key, the encrypted salts, their MAC and the
/// protocol. The salts are encrypted and the MAC is public, so neither is secret.
#[derive(Debug, PartialEq, Eq)]
pub struct HmacSecretInput {
    key_agreement: PeerKey,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    protocol: Option<u64>,
}

/// The extensions of a makeCredential request this authenticator processes; any other is ignored
/// (§6.1.2 step 19.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MakeCredentialExtensions {
    /// `credProtect`.
    pub cred_protect: Option<CredProtect>,
    /// `"hmac-secret": true`.
    pub hmac_secret: bool,
    /// `hmac-secret-mc`.
    pub hmac_secret_mc: Option<HmacSecretInput>,
}

/// Reads the `extensions` map of makeCredential. A credProtect value outside 1..3 is
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE, as OpenSK answers it: §12.1 defines only those three. An
/// hmac-secret-mc input without one of its required members sets `missing`.
pub(super) fn make_credential_extensions(
    decoder: &mut Decoder<'_>,
    missing: &mut bool,
) -> Result<MakeCredentialExtensions, cbor::Error> {
    decoder.map(|entries| {
        let mut extensions = MakeCredentialExtensions::default();
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text(CRED_PROTECT) => {
                    let level = CredProtect::try_from(value.unsigned()?)
                        .map_err(|_| cbor::Error::UnexpectedType)?;
                    extensions.cred_protect = Some(level);
                }
                Key::Text(HMAC_SECRET) => extensions.hmac_secret = value.bool()?,
                Key::Text(HMAC_SECRET_MC) => {
                    extensions.hmac_secret_mc = hmac_secret_input(value, missing)?;
                }
                _ => value.skip()?,
            }
        }
        Ok(extensions)
    })
}

/// Reads the `extensions` map of getAssertion into its hmac-secret input, if any. An input
/// without one of its required members sets `missing`.
pub(super) fn get_assertion_extensions(
    decoder: &mut Decoder<'_>,
    missing: &mut bool,
) -> Result<Option<HmacSecretInput>, cbor::Error> {
    decoder.map(|entries| {
        let mut input = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Text(HMAC_SECRET) => input = hmac_secret_input(value, missing)?,
                _ => value.skip()?,
            }
        }
        Ok(input)
    })
}

/// Reads an hmac-secret input map: keyAgreement (1), saltEnc (2) and saltAuth (3) required,
/// pinUvAuthProtocol (4) optional. `None`, with `missing` set, without a required member.
fn hmac_secret_input(
    decoder: &mut Decoder<'_>,
    missing: &mut bool,
) -> Result<Option<HmacSecretInput>, cbor::Error> {
    decoder.map(|entries| {
        let mut key_agreement = None;
        let mut salt_enc = None;
        let mut salt_auth = None;
        let mut protocol = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => key_agreement = Some(peer_key(value)?),
                Key::Int(0x02) => salt_enc = Some(value.bytes()?.to_vec()),
                Key::Int(0x03) => salt_auth = Some(value.bytes()?.to_vec()),
                Key::Int(0x04) => protocol = Some(value.unsigned()?),
                _ => value.skip()?,
            }
        }
        let (Some(key_agreement), Some(salt_enc), Some(salt_auth)) =
            (key_agreement, salt_enc, salt_auth)
        else {
            *missing = true;
            return Ok(None);
        };
        Ok(Some(HmacSecretInput {
            key_agreement,
            salt_enc,
            salt_auth,
            protocol,
        }))
    })
}

/// The decrypted salts of an hmac-secret input and the shared secret their outputs are
/// encrypted with. Both are wiped on drop.
pub(super) struct Salts {
    secret: SharedSecret,
    salts: Zeroizing<[u8; MAX_SALTS_LEN]>,
    /// 32 for salt1 alone, 64 with salt2.
    len: usize,
}

impl core::fmt::Debug for Salts {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Salts")
            .field("secret", &self.secret)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// What the `hmac-secret` output of the authenticator data holds.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HmacSecretOutput {
    /// makeCredential: `true`, the credential has its CredRandom values.
    Created,
    /// getAssertion: the encrypted outputs.
    Secret(Vec<u8>),
}

/// The extension outputs of one authenticator data (§12): each present only when the request
/// carried its extension, so no output is unsolicited (§12.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Outputs {
    pub(super) cred_protect: Option<CredProtect>,
    pub(super) hmac_secret: Option<HmacSecretOutput>,
    pub(super) hmac_secret_mc: Option<Vec<u8>>,
}

impl Outputs {
    /// Whether there is no output, and so no ED flag and no extensions map.
    pub(super) const fn is_empty(&self) -> bool {
        self.cred_protect.is_none() && self.hmac_secret.is_none() && self.hmac_secret_mc.is_none()
    }

    /// The `extensions` map of the authenticator data (WebAuthn L3 §6.1), keys in canonical
    /// order: `credProtect` and `hmac-secret` have the same length and sort bytewise, then the
    /// longer `hmac-secret-mc`.
    pub(super) fn encode(&self) -> Result<Vec<u8>, StatusCode> {
        let mut buffer = [0u8; MAX_OUTPUTS_LEN];
        let mut encoder = Encoder::new(&mut buffer);
        self.write(&mut encoder).map_err(|Full| StatusCode::Other)?;
        Ok(encoder.as_bytes().to_vec())
    }

    fn write(&self, encoder: &mut Encoder<'_>) -> Result<(), Full> {
        let members = usize::from(self.cred_protect.is_some())
            + usize::from(self.hmac_secret.is_some())
            + usize::from(self.hmac_secret_mc.is_some());
        encoder.map(members)?;
        if let Some(level) = self.cred_protect {
            encoder.text(CRED_PROTECT)?.unsigned(level as u64)?;
        }
        match &self.hmac_secret {
            Some(HmacSecretOutput::Created) => {
                encoder.text(HMAC_SECRET)?.bool(true)?;
            }
            Some(HmacSecretOutput::Secret(output)) => {
                encoder.text(HMAC_SECRET)?.bytes(output)?;
            }
            None => {}
        }
        if let Some(output) = &self.hmac_secret_mc {
            encoder.text(HMAC_SECRET_MC)?.bytes(output)?;
        }
        Ok(())
    }
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// The salts of an hmac-secret input (§12.7 authenticator processing): the protocol, 1 when
    /// absent; `decapsulate` on the platform key, CTAP1_ERR_INVALID_PARAMETER when it fails, as
    /// authenticatorClientPIN answers it (§6.5.5.5 step 5.4); `verify(saltEnc, saltAuth)`,
    /// CTAP2_ERR_PIN_AUTH_INVALID when it fails; then `decrypt`, CTAP1_ERR_INVALID_PARAMETER
    /// when it fails or gives other than 32 or 64 bytes.
    pub(super) fn salts(&self, input: &HmacSecretInput) -> Result<Salts, StatusCode> {
        let protocol = match input.protocol {
            None => Protocol::One,
            Some(number) => Protocol::from_number(number).ok_or(StatusCode::InvalidParameter)?,
        };
        let secret = decapsulate(
            &self.client_pin,
            &self.crypto,
            protocol,
            input.key_agreement,
        )?;
        if !secret.verify(&self.crypto, &[&input.salt_enc], &input.salt_auth) {
            return Err(StatusCode::PinAuthInvalid);
        }
        let mut salts = Zeroizing::new([0u8; MAX_SALTS_LEN]);
        // A ciphertext longer than two salts fails here, being too long for the buffer.
        let len = secret
            .decrypt(&self.crypto, &input.salt_enc, &mut salts[..])
            .map_err(|_| StatusCode::InvalidParameter)?;
        if len != KEY_LEN && len != MAX_SALTS_LEN {
            return Err(StatusCode::InvalidParameter);
        }
        Ok(Salts { secret, salts, len })
    }

    /// The hmac-secret output for `salts` under `cred_random`: `HMAC-SHA-256(CredRandom, salt)`
    /// for each salt, concatenated and encrypted with the shared secret (§12.7).
    pub(super) fn hmac_secret_output(
        &mut self,
        salts: &Salts,
        cred_random: &[u8; KEY_LEN],
    ) -> Result<Vec<u8>, StatusCode> {
        let mut outputs = Zeroizing::new([0u8; MAX_SALTS_LEN]);
        let (salt_blocks, _) = salts.salts[..salts.len].as_chunks::<KEY_LEN>();
        let (output_blocks, _) = outputs.as_chunks_mut::<KEY_LEN>();
        for (salt, output) in salt_blocks.iter().zip(output_blocks) {
            output.copy_from_slice(&self.crypto.hmac_sha256(cred_random, &[salt])[..]);
        }
        let mut encrypted = [0u8; MAX_OUTPUT_LEN];
        let len = salts
            .secret
            .encrypt(&mut self.crypto, &outputs[..salts.len], &mut encrypted)
            .map_err(|_| StatusCode::Other)?;
        Ok(encrypted[..len].to_vec())
    }
}

#[cfg(test)]
mod tests;

//! authenticatorConfig (CTAP 2.2 §6.11): `toggleAlwaysUv`, the one subcommand this
//! authenticator offers.

use alloc::vec::Vec;

use super::client_pin::Bytes;
use super::{Authenticator, StatusCode};
use crate::cbor::{Decoder, Key};
use crate::crypto::{Crypto, KEY_LEN};
use crate::pin::Permissions;
use crate::storage::Storage;
use crate::ui::Ui;

/// The subcommand code of toggleAlwaysUv (§6.11.2).
const TOGGLE_ALWAYS_UV: u8 = 0x02;

/// The fixed prefix of the message a config pinUvAuthParam authenticates (§6.11 step 4.2): 32
/// bytes of 0xff and the command code 0x0d.
const MESSAGE_PREFIX: [u8; 33] = {
    let mut prefix = [0xFF; 33];
    prefix[32] = 0x0D;
    prefix
};

/// An authenticatorConfig request, owning its members. Not `Clone`: its `pinUvAuthParam` wipes
/// itself when the one request is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigRequest {
    sub_command: u64,
    /// `subCommandParams` as received, which the pinUvAuthParam authenticates.
    params: Option<Vec<u8>>,
    protocol: Option<u64>,
    pin_uv_auth_param: Option<Bytes<KEY_LEN>>,
}

/// Parses the CBOR parameters of authenticatorConfig (§6.11). Unknown members are ignored (§8);
/// a missing `subCommand` is CTAP2_ERR_MISSING_PARAMETER (step 1).
pub(super) fn parse(parameters: &[u8]) -> Result<ConfigRequest, StatusCode> {
    let mut decoder = Decoder::new(parameters);
    let read = decoder.map(|entries| {
        let mut sub_command = None;
        let mut params = None;
        let mut protocol = None;
        let mut pin_uv_auth_param = None;
        while let Some(key) = entries.next_key()? {
            let value = entries.value();
            match key {
                Key::Int(0x01) => sub_command = Some(value.unsigned()?),
                Key::Int(0x02) => {
                    let item = value.encoded_item()?;
                    // A map, as §6.11 defines it.
                    Decoder::new(item).map(|_| Ok(()))?;
                    params = Some(item.to_vec());
                }
                Key::Int(0x03) => protocol = Some(value.unsigned()?),
                Key::Int(0x04) => pin_uv_auth_param = Some(Bytes::new(value.bytes()?)),
                _ => value.skip()?,
            }
        }
        Ok((sub_command, params, protocol, pin_uv_auth_param))
    });
    let (sub_command, params, protocol, pin_uv_auth_param) = read.map_err(StatusCode::from)?;
    decoder.finish().map_err(StatusCode::from)?;
    Ok(ConfigRequest {
        sub_command: sub_command.ok_or(StatusCode::MissingParameter)?,
        params,
        protocol,
        pin_uv_auth_param,
    })
}

impl<C: Crypto, S: Storage> Authenticator<C, S> {
    /// Runs an authenticatorConfig request (§6.11). A subcommand other than toggleAlwaysUv is
    /// CTAP1_ERR_INVALID_PARAMETER (step 2). The authenticator is always protected by user
    /// verification (built-in UV is the device unlock), so step 4 always applies: a
    /// pinUvAuthParam over `32 × 0xff || 0x0d || subCommand || subCommandParams` from a token with
    /// the `acfg` permission, or CTAP2_ERR_PIN_AUTH_INVALID.
    pub(super) fn config<U: Ui>(
        &mut self,
        request: &ConfigRequest,
        ui: &mut U,
    ) -> Result<(), StatusCode> {
        if request.sub_command != u64::from(TOGGLE_ALWAYS_UV) {
            return Err(StatusCode::InvalidParameter);
        }
        let param = request
            .pin_uv_auth_param
            .as_ref()
            .ok_or(StatusCode::PuatRequired)?;
        let protocol = Self::param_protocol(request.protocol)?;
        let sub_command = [TOGGLE_ALWAYS_UV];
        let message: [&[u8]; 3] = [
            &MESSAGE_PREFIX,
            &sub_command,
            request.params.as_deref().unwrap_or_default(),
        ];
        let verified = self.client_pin.verify_token(
            &self.crypto,
            protocol,
            &message,
            param.get().unwrap_or_default(),
            ui.now_ms(),
        );
        if !verified
            || !self
                .client_pin
                .has_permission(Permissions::AUTHENTICATOR_CONFIG)
        {
            return Err(StatusCode::PinAuthInvalid);
        }
        // §6.11.2: enabling and disabling are both supported; makeCredUvNotRqd is always false
        // here, so there is nothing to restore with it.
        self.toggle_always_uv();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

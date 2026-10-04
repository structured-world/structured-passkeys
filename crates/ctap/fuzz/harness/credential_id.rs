//! Credential ID opening driven by arbitrary bytes: the checks of the fuzz target.
//!
//! The bytes are tried twice: as a credential ID (almost never authentic, so this exercises the
//! length, version and tag checks) and as a plaintext sealed under the device's own key (which
//! reaches the plaintext parser). Whatever opens must seal and open back to itself.

use structured_passkeys_ctap::credential_id::{self, OpenError, VERSION};
use structured_passkeys_ctap::crypto::{Crypto, KEY_LEN, NONCE_LEN};
use structured_passkeys_ctap::keys::KeyRing;
use structured_passkeys_ctap::soft::SoftCrypto;

const RP: &str = "example.com";

/// Runs one input; panics on any broken property.
pub fn run(data: &[u8]) {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let keys = KeyRing::new(&mut crypto);

    if let Ok(credential) = credential_id::open(&crypto, &keys, RP, data, 0) {
        round_trip(&mut crypto, &keys, &credential);
    }

    let mut nonce = [0u8; NONCE_LEN];
    crypto.random(&mut nonce);
    let mut aad = vec![VERSION];
    aad.extend_from_slice(&crypto.sha256(&[RP.as_bytes()]));
    let mut plaintext = data.to_vec();
    let tag = crypto.aes256_gcm_seal(&keys.wrap_key(&crypto), &nonce, &aad, &mut plaintext);
    let id = [&[VERSION][..], &nonce, &plaintext, &tag].concat();
    match credential_id::open(&crypto, &keys, RP, &id, 0) {
        Ok(credential) => round_trip(&mut crypto, &keys, &credential),
        // A plaintext that is not a credential, or too long for any credential ID.
        Err(OpenError::Plaintext | OpenError::Length) => {}
        Err(error) => panic!("authentic ID refused as {error:?}"),
    }
}

/// An opened credential seals again and opens to the same value, for its RP only, on a device at
/// its own reset ID or at 0; any other nonzero reset ID revokes it.
fn round_trip(crypto: &mut SoftCrypto, keys: &KeyRing, credential: &credential_id::Credential) {
    let id = credential_id::seal(crypto, keys, RP, credential).expect("an opened credential fits");
    assert!(id.len() <= credential_id::MAX_CREDENTIAL_ID_LEN);
    for reset_id in [credential.reset_id, 0] {
        assert_eq!(
            credential_id::open(crypto, keys, RP, &id, reset_id).as_ref(),
            Ok(credential)
        );
    }
    assert_eq!(
        credential_id::open(crypto, keys, "example.org", &id, 0),
        Err(OpenError::Authentication)
    );
    let other = credential.reset_id.wrapping_add(1).max(1);
    if other != credential.reset_id {
        assert_eq!(
            credential_id::open(crypto, keys, RP, &id, other),
            Err(OpenError::Revoked)
        );
    }
}

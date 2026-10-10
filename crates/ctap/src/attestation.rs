//! Credential public keys in COSE form, packed self attestation, and the self-signed certificate
//! a CTAP1/U2F registration carries.
//!
//! Self attestation (WebAuthn L3 §8.2, packed format without `x5c`): the statement is signed by
//! the credential's own private key, so nothing secret is compiled into the application. A U2F
//! registration must carry an X.509 attestation certificate (U2F raw messages §4.3); it is a
//! certificate of the credential's own key, signed by that key, the U2F form of self attestation:
//! it tells the RP nothing beyond the public key it receives anyway, so no two registrations can
//! be linked through it.

use alloc::vec::Vec;

use crate::cbor::{Encoder, Full};
use crate::crypto::{Crypto, CryptoError, KEY_LEN, PUBLIC_KEY_LEN, Signature};

/// COSE algorithm ES256: ECDSA with SHA-256 on P-256 (RFC 9053 §2.1).
pub const ES256: i64 = -7;

/// COSE key type EC2 (RFC 9053 §7.1).
const KTY_EC2: u64 = 2;
/// COSE curve P-256 (RFC 9053 §7.1).
const CRV_P256: u64 = 1;

/// Writes an uncompressed P-256 public key as a COSE_Key map `{1: 2, 3: -7, -1: 1, -2: x, -3:
/// y}` (RFC 9052 §7, RFC 9053 §7.1.1), keys in CTAP2 canonical order.
///
/// # Errors
///
/// [`Full`] when the buffer has no room.
pub fn encode_cose_key(
    encoder: &mut Encoder<'_>,
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), Full> {
    let (x, y) = public_key[1..].split_at(KEY_LEN);
    encoder
        .map(5)?
        .unsigned(1)?
        .unsigned(KTY_EC2)?
        .unsigned(3)?
        .int(ES256)?
        .int(-1)?
        .unsigned(CRV_P256)?
        .int(-2)?
        .bytes(x)?
        .int(-3)?
        .bytes(y)?;
    Ok(())
}

/// The packed self-attestation signature: ECDSA under the credential's private key over
/// `authenticatorData || clientDataHash` (WebAuthn L3 §8.2).
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] for a private key outside P-256's range.
pub fn sign_self_attestation<C: Crypto>(
    crypto: &mut C,
    private_key: &[u8; KEY_LEN],
    authenticator_data: &[u8],
    client_data_hash: &[u8; KEY_LEN],
) -> Result<Signature, CryptoError> {
    let digest = crypto.sha256(&[authenticator_data, client_data_hash]);
    crypto.p256_sign(private_key, &digest)
}

/// Writes the packed attestation statement `{"alg": -7, "sig": signature}` (WebAuthn L3 §8.2,
/// self attestation: no `x5c`).
///
/// # Errors
///
/// [`Full`] when the buffer has no room.
pub fn encode_packed_statement(
    encoder: &mut Encoder<'_>,
    signature: &Signature,
) -> Result<(), Full> {
    encoder
        .map(2)?
        .text("alg")?
        .int(ES256)?
        .text("sig")?
        .bytes(signature.as_der())?;
    Ok(())
}

/// DER tag SEQUENCE (X.690 §8.9).
const SEQUENCE: u8 = 0x30;
/// DER tag SET (X.690 §8.11).
const SET: u8 = 0x31;
/// DER tag INTEGER (X.690 §8.3).
const INTEGER: u8 = 0x02;
/// DER tag BIT STRING (X.690 §8.6).
const BIT_STRING: u8 = 0x03;
/// DER tag UTF8String (X.690 §8.23).
const UTF8_STRING: u8 = 0x0C;
/// DER tag UTCTime (X.690 §11.8).
const UTC_TIME: u8 = 0x17;
/// DER tag GeneralizedTime (X.690 §11.7).
const GENERALIZED_TIME: u8 = 0x18;

/// AlgorithmIdentifier ecdsa-with-SHA256, OID 1.2.840.10045.4.3.2, with no parameters (RFC 5758
/// §3.2).
const ECDSA_WITH_SHA256: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
/// The AlgorithmIdentifier of a P-256 public key: id-ecPublicKey (1.2.840.10045.2.1) with the
/// named curve secp256r1 (1.2.840.10045.3.1.7) as parameter (RFC 5480 §2.1.1).
const P256_PUBLIC_KEY: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x03, 0x01, 0x07,
];
/// The attribute type commonName, OID 2.5.4.3 (RFC 5280 Appendix A.1).
const COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
/// The common name of the certificate's issuer and subject.
const U2F_COMMON_NAME: &[u8] = b"Structured Passkeys U2F";
/// notBefore: the device has no calendar, so the start of the UTCTime range, 2000-01-01.
const NOT_BEFORE: &[u8] = b"000101000000Z";
/// notAfter: no well-defined expiration date (RFC 5280 §4.1.2.5).
const NOT_AFTER: &[u8] = b"99991231235959Z";

/// Appends the DER encoding of a value of `tag` with `content` to `out` (X.690 §8.1.3: the
/// shortest length form).
fn der(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let length = content.len();
    if let Ok(short) = u8::try_from(length)
        && short < 0x80
    {
        out.push(short);
    } else if let Ok(one) = u8::try_from(length) {
        out.extend_from_slice(&[0x81, one]);
    } else {
        // Every value here is far below 64 KiB: a certificate of one P-256 key.
        let two = u16::try_from(length).expect("a certificate value fits 16 bits");
        out.push(0x82);
        out.extend_from_slice(&two.to_be_bytes());
    }
    out.extend_from_slice(content);
}

/// The DER of `parts` concatenated inside a value of `tag`.
fn der_of(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.concat();
    let mut out = Vec::with_capacity(content.len() + 4);
    der(&mut out, tag, &content);
    out
}

/// The issuer and subject Name: a single commonName (RFC 5280 §4.1.2.4 requires a non-empty
/// issuer).
fn u2f_name() -> Vec<u8> {
    let value = der_of(UTF8_STRING, &[U2F_COMMON_NAME]);
    let attribute = der_of(SEQUENCE, &[COMMON_NAME, &value]);
    let rdn = der_of(SET, &[&attribute]);
    der_of(SEQUENCE, &[&rdn])
}

/// The certificate of a U2F registration (U2F raw messages §4.3): an X.509 v1 certificate, as
/// RFC 5280 §4.1.2.1 asks of one without extensions, of the credential's public key, issued by
/// and to "Structured Passkeys U2F" and signed with ECDSA-SHA256 by the credential's own private
/// key. The serial number comes from the public key, so it is unique per key without a counter
/// and positive (X.690 §8.3.2: no leading bit set).
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] for a private key outside P-256's range.
pub fn u2f_certificate<C: Crypto>(
    crypto: &mut C,
    private_key: &[u8; KEY_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let mut serial = [0u8; 8];
    serial.copy_from_slice(&crypto.sha256(&[public_key])[..8]);
    // Positive with a nonzero first byte, so the encoding is the shortest one.
    serial[0] = (serial[0] & 0x7F) | 0x40;
    let serial = der_of(INTEGER, &[&serial]);
    let name = u2f_name();
    let validity = der_of(
        SEQUENCE,
        &[
            &der_of(UTC_TIME, &[NOT_BEFORE]),
            &der_of(GENERALIZED_TIME, &[NOT_AFTER]),
        ],
    );
    let key_bits = der_of(BIT_STRING, &[&[0x00], public_key]);
    let key_info = der_of(SEQUENCE, &[P256_PUBLIC_KEY, &key_bits]);
    let tbs = der_of(
        SEQUENCE,
        &[
            &serial,
            ECDSA_WITH_SHA256,
            &name,
            &validity,
            &name,
            &key_info,
        ],
    );
    let digest = crypto.sha256(&[&tbs]);
    let signature = crypto.p256_sign(private_key, &digest)?;
    let signature_bits = der_of(BIT_STRING, &[&[0x00], signature.as_der()]);
    Ok(der_of(
        SEQUENCE,
        &[&tbs, ECDSA_WITH_SHA256, &signature_bits],
    ))
}

#[cfg(test)]
mod tests;

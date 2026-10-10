//! COSE keys and packed self attestation: encodings written out by hand from RFC 9052/9053 and
//! WebAuthn L3 §8.2, signatures checked with the independent `p256` verifier.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{DerSignature, VerifyingKey};

use super::{
    ES256, encode_cose_key, encode_packed_statement, sign_self_attestation, u2f_certificate,
};
use crate::cbor::{Encoder, validate};
use crate::crypto::{Crypto, KEY_LEN, PUBLIC_KEY_LEN};
use crate::soft::SoftCrypto;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// The credential key of the derivation vectors (tests/vectors/derive.py).
fn private_key() -> [u8; KEY_LEN] {
    hex("1c25ee63dee5fe30ce9c52ab615f52ac394a85337799970d800c083971cfb721")
        .try_into()
        .expect("32 bytes")
}

fn public_key() -> [u8; PUBLIC_KEY_LEN] {
    hex("045d31fcf65ebd9f1f252c1d9fd97dd225f3bf7dde1c4967b09457ca4156889a0407903bd11c6253ad24a56919c313027951af0759d9ce749aa8bbcf62290f718b")
        .try_into()
        .expect("65 bytes")
}

/// The COSE_Key is `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in canonical key order (unsigned keys
/// before negative ones): A5 01 02 03 26 20 01 21 58 20 x 22 58 20 y.
#[test]
fn the_cose_key_is_ec2_es256_p256() {
    let public_key = public_key();
    let mut buffer = [0u8; 128];
    let mut encoder = Encoder::new(&mut buffer);
    encode_cose_key(&mut encoder, &public_key).expect("fits");
    let expected = [
        &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20][..],
        &public_key[1..33],
        &[0x22, 0x58, 0x20],
        &public_key[33..],
    ]
    .concat();
    assert_eq!(encoder.as_bytes(), &expected[..]);
    assert_eq!(validate(encoder.as_bytes()), Ok(()));
}

/// The self-attestation signature verifies under the credential public key over SHA-256 of
/// authenticatorData || clientDataHash; over anything else it does not.
#[test]
fn self_attestation_signs_auth_data_and_client_data_hash() {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let auth_data = [0xAD; 37];
    let client_data_hash = [0xCD; KEY_LEN];
    let signature =
        sign_self_attestation(&mut crypto, &private_key(), &auth_data, &client_data_hash)
            .expect("valid key");
    let verifier = VerifyingKey::from_sec1_bytes(&public_key()).expect("valid point");
    let der = DerSignature::from_bytes(signature.as_der()).expect("DER signature");
    let digest = crypto.sha256(&[&auth_data, &client_data_hash]);
    assert!(verifier.verify_prehash(&digest, &der).is_ok());
    let other = crypto.sha256(&[&auth_data, &[0xCE; KEY_LEN]]);
    assert!(verifier.verify_prehash(&other, &der).is_err());
}

/// attStmt is `{"alg": -7, "sig": signature}` with "alg" first (equal lengths, bytewise order)
/// and no x5c: A2 63 'alg' 26 63 'sig' 58 len signature.
#[test]
fn the_packed_statement_is_alg_and_sig() {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let signature = crypto
        .p256_sign(&private_key(), &[0x5A; KEY_LEN])
        .expect("valid key");
    let mut buffer = [0u8; 128];
    let mut encoder = Encoder::new(&mut buffer);
    encode_packed_statement(&mut encoder, &signature).expect("fits");
    let der = signature.as_der();
    let expected = [
        &[
            0xA2, 0x63, b'a', b'l', b'g', 0x26, 0x63, b's', b'i', b'g', 0x58,
        ][..],
        &[u8::try_from(der.len()).expect("short")],
        der,
    ]
    .concat();
    assert_eq!(encoder.as_bytes(), &expected[..]);
    assert_eq!(validate(encoder.as_bytes()), Ok(()));
    assert_eq!(ES256, -7);
}

/// The U2F certificate is RFC 5280's Certificate of the credential key, written out here by hand
/// in DER (X.690): a v1 TBSCertificate (no version field) with an 8-byte positive serial number
/// from the SHA-256 of the public key, ecdsa-with-SHA256, issuer and subject CN "Structured
/// Passkeys U2F", validity 2000-01-01 to 9999-12-31 23:59:59 and the P-256 key; then the same
/// algorithm and a BIT STRING of the DER signature, which verifies under the credential key over
/// the TBSCertificate.
#[test]
fn the_u2f_certificate_is_self_signed_by_the_credential_key() {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let public_key = public_key();
    let certificate = u2f_certificate(&mut crypto, &private_key(), &public_key).expect("valid key");
    let mut serial = crypto.sha256(&[&public_key])[..8].to_vec();
    serial[0] = (serial[0] & 0x7F) | 0x40;
    let algorithm = [
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];
    let name = [
        &[
            0x30, 0x22, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x17,
        ][..],
        b"Structured Passkeys U2F",
    ]
    .concat();
    let validity = [
        &[0x30, 0x20, 0x17, 0x0D][..],
        b"000101000000Z",
        &[0x18, 0x0F],
        b"99991231235959Z",
    ]
    .concat();
    let key_info = [
        &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ][..],
        &public_key,
    ]
    .concat();
    // 10 + 12 + 36 + 34 + 36 + 91 = 219 bytes of content.
    let tbs = [
        &[0x30, 0x81, 0xDB, 0x02, 0x08][..],
        &serial,
        &algorithm,
        &name,
        &validity,
        &name,
        &key_info,
    ]
    .concat();
    assert_eq!(tbs.len(), 3 + 219);
    // The certificate: SEQUENCE { tbs, algorithm, BIT STRING { 0, signature } }.
    let content_len = usize::from(u16::from_be_bytes([certificate[2], certificate[3]]));
    assert_eq!(certificate[..2], [0x30, 0x82]);
    assert_eq!(certificate.len(), 4 + content_len);
    let body = &certificate[4..];
    assert_eq!(body[..tbs.len()], tbs[..]);
    let rest = &body[tbs.len()..];
    assert_eq!(rest[..algorithm.len()], algorithm);
    let bits = &rest[algorithm.len()..];
    assert_eq!(bits[0], 0x03, "BIT STRING");
    assert_eq!(
        usize::from(bits[1]),
        bits.len() - 2,
        "the rest is the BIT STRING"
    );
    assert_eq!(bits[2], 0x00, "no unused bits");
    let verifier = VerifyingKey::from_sec1_bytes(&public_key).expect("valid point");
    let der = DerSignature::from_bytes(&bits[3..]).expect("DER signature");
    assert!(
        verifier
            .verify_prehash(&crypto.sha256(&[&tbs]), &der)
            .is_ok()
    );
}

//! HKDF against the RFC 5869 Appendix A vectors, AES-256-CBC against SP 800-38A, P-256 ECDH
//! against RFC 5903, and the P-256 private-key range check at its boundaries. Expected bytes are
//! copied from the specifications. Also the software platform's redacted Debug output.

use super::{Crypto, CryptoError, KEY_LEN, PUBLIC_KEY_LEN, hkdf_sha256, is_p256_private_key};
use crate::soft::SoftCrypto;

fn crypto() -> SoftCrypto {
    SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN])
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// RFC 5869 A.1: the first 32 bytes of OKM are T(1), the block this HKDF returns. A wrong salt,
/// IKM or info order gives a different block.
#[test]
fn hkdf_matches_rfc5869_test_case_1() {
    let ikm = [0x0B; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm = hkdf_sha256(&crypto(), &salt, &ikm, &info, &[]);
    assert_eq!(
        okm[..],
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
    );
    // The info split between label and suffix is the same info.
    let split = hkdf_sha256(&crypto(), &salt, &ikm, &info[..5], &info[5..]);
    assert_eq!(split[..], okm[..]);
}

/// RFC 5869 A.3: an empty salt is HashLen zeros and an empty info is allowed.
#[test]
fn hkdf_matches_rfc5869_test_case_3() {
    let okm = hkdf_sha256(&crypto(), &[], &[0x0B; 22], &[], &[]);
    assert_eq!(
        okm[..],
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")[..]
    );
}

/// A P-256 private key is 0 < d < n (SEC 1 §3.2.1): zero, n and above are refused, 1 and n - 1
/// accepted. A check that compared the wrong way round or forgot zero would pass a bad key.
#[test]
fn p256_private_keys_are_between_zero_and_the_order() {
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let key = |bytes: &[u8]| -> [u8; KEY_LEN] { bytes.try_into().expect("32 bytes") };
    let mut below = key(&order);
    below[KEY_LEN - 1] = 0x50;
    let mut above = key(&order);
    above[KEY_LEN - 1] = 0x52;
    let mut one = [0u8; KEY_LEN];
    one[KEY_LEN - 1] = 1;

    assert!(!is_p256_private_key(&[0u8; KEY_LEN]), "zero");
    assert!(is_p256_private_key(&one), "one");
    assert!(is_p256_private_key(&below), "n - 1");
    assert!(!is_p256_private_key(&key(&order)), "n");
    assert!(!is_p256_private_key(&above), "n + 1");
    assert!(!is_p256_private_key(&[0xFF; KEY_LEN]), "2^256 - 1");
    // A difference only in the top byte: 0x7F... is far below n.
    let mut high = [0u8; KEY_LEN];
    high[0] = 0x7F;
    assert!(is_p256_private_key(&high), "0x7f00..00");
}

/// SP 800-38A F.2.5 and F.2.6, CBC-AES256: encryption and decryption of the four-block example,
/// in place, chained from the IV.
#[test]
fn aes256_cbc_matches_sp800_38a() {
    let key: [u8; KEY_LEN] =
        hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .try_into()
            .expect("32 bytes");
    let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f")
        .try_into()
        .expect("16 bytes");
    let plaintext = hex(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ));
    let ciphertext = hex(concat!(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
        "9cfc4e967edb808d679f777bc6702c7d",
        "39f23369a9d9bacfa530e26304231461",
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
    ));
    let mut data = plaintext.clone();
    assert_eq!(crypto().aes256_cbc_encrypt(&key, &iv, &mut data), Ok(()));
    assert_eq!(data, ciphertext);
    assert_eq!(crypto().aes256_cbc_decrypt(&key, &iv, &mut data), Ok(()));
    assert_eq!(data, plaintext);
}

/// AES-CBC without padding takes whole blocks only, and leaves partial input untouched.
#[test]
fn aes256_cbc_refuses_partial_blocks() {
    let mut data = [7u8; 17];
    assert_eq!(
        crypto().aes256_cbc_encrypt(&[0; KEY_LEN], &[0; 16], &mut data),
        Err(CryptoError::Length)
    );
    assert_eq!(
        crypto().aes256_cbc_decrypt(&[0; KEY_LEN], &[0; 16], &mut data),
        Err(CryptoError::Length)
    );
    assert_eq!(data, [7u8; 17]);
}

/// RFC 5903 §8.1, the 256-bit random ECP group: each side's ECDH of its private key with the
/// other's public point gives the shared x-coordinate, and each public point is its scalar times
/// the base point.
#[test]
fn p256_ecdh_matches_rfc5903() {
    let i: [u8; KEY_LEN] = hex("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433")
        .try_into()
        .expect("32 bytes");
    let r: [u8; KEY_LEN] = hex("c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53")
        .try_into()
        .expect("32 bytes");
    let gi: [u8; PUBLIC_KEY_LEN] = hex(concat!(
        "04",
        "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180",
        "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
    ))
    .try_into()
    .expect("65 bytes");
    let gr: [u8; PUBLIC_KEY_LEN] = hex(concat!(
        "04",
        "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63",
        "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab",
    ))
    .try_into()
    .expect("65 bytes");
    let shared = hex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");

    assert_eq!(crypto().p256_public_key(&i), Ok(gi));
    assert_eq!(crypto().p256_public_key(&r), Ok(gr));
    assert_eq!(
        crypto().p256_ecdh(&i, &gr).map(|z| z.to_vec()),
        Ok(shared.clone())
    );
    assert_eq!(crypto().p256_ecdh(&r, &gi).map(|z| z.to_vec()), Ok(shared));
}

/// ECDH refuses a peer point that is not on the curve: y changed by one bit.
#[test]
fn p256_ecdh_refuses_a_point_off_the_curve() {
    let mut scalar = [0u8; KEY_LEN];
    scalar[KEY_LEN - 1] = 1;
    let mut point = crypto().p256_public_key(&scalar).expect("a valid scalar");
    point[PUBLIC_KEY_LEN - 1] ^= 1;
    assert_eq!(
        crypto().p256_ecdh(&scalar, &point).map(|z| z.to_vec()),
        Err(CryptoError::InvalidPoint)
    );
}

/// The software platform's node derives every key and its seed predicts every nonce: Debug
/// output prints neither.
#[test]
fn soft_crypto_debug_output_hides_the_node_and_the_seed() {
    let debug = format!("{:?}", crypto());
    assert_eq!(debug, "SoftCrypto { counter: 0, .. }");
}

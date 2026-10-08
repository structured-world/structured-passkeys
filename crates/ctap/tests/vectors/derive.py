# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43"]
# ///
"""Computes the key-derivation and credential-ID vectors of crates/ctap independently of its code.

Run with `uv run crates/ctap/tests/vectors/derive.py`; the printed values are the expected bytes
in crates/ctap/src/keys/tests.rs and crates/ctap/src/credential_id/tests.rs. With
`--seeds <dir>` it also writes every plaintext and credential ID into `<dir>` as seeds of the
credential-id fuzz corpus, each named by the SHA-1 of its bytes as cargo-fuzz names corpus
entries, so writing into the local, uncommitted crates/ctap/fuzz/corpus/credential-id adds what
is missing and duplicates nothing.
"""

import hashlib
import hmac
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Order of the P-256 group (SEC 2, section 2.4.2).
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

NODE = bytes([0x11] * 32)
SEED = bytes([0x22] * 32)
CS = bytes([0x33] * 32)
SLOT_TAG = bytes([0x44] * 16)
K_DEV = bytes([0x55] * 32)
RP_ID = b"example.com"


def hkdf(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    """HKDF-SHA-256 (RFC 5869) with a 32-byte output."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def first_random_block() -> bytes:
    """The first 32 bytes the software platform draws: SHA-256(seed || 0 as u64 big-endian)."""
    return hashlib.sha256(SEED + (0).to_bytes(8, "big")).digest()


def credential_id(plaintext: bytes, k_wrap: bytes) -> bytes:
    nonce = first_random_block()[:12]
    aad = b"\x01" + hashlib.sha256(RP_ID).digest()
    sealed = AESGCM(k_wrap).encrypt(nonce, plaintext, aad)  # ciphertext || tag
    return b"\x01" + nonce + sealed


def main() -> None:
    k_root = hkdf(b"structured-passkeys/v1", NODE, b"root")
    k_wrap = hkdf(b"", k_root, b"credential-wrap")
    k_cred = hkdf(b"", k_root, b"credential-key")
    print("k_root", k_root.hex())
    print("k_wrap", k_wrap.hex())

    for counter in range(256):
        d = hkdf(CS, k_cred, b"es256" + bytes([counter]))
        if 0 < int.from_bytes(d, "big") < N:
            break
    print("credential_key_counter", counter)
    print("credential_key", d.hex())
    # The key after a rejected counter 0, for the rejection test.
    print("credential_key_counter_1", hkdf(CS, k_cred, b"es256\x01").hex())
    public = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1()).public_key()
    print(
        "credential_public_key",
        public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ).hex(),
    )

    # Non-discoverable device-only key: the same derivation with K_dev in place of K_root.
    k_dev_cred = hkdf(b"", K_DEV, b"credential-key")
    for counter in range(256):
        device = hkdf(CS, k_dev_cred, b"es256" + bytes([counter]))
        if 0 < int.from_bytes(device, "big") < N:
            break
    print("device_credential_key_counter", counter)
    print("device_credential_key", device.hex())

    # Seed-recoverable, non-discoverable: {1: 1, 2: -7, 3: cs, 6: 1, 7: false, 11: 0}.
    seed_plaintext = (
        bytes([0xA6, 0x01, 0x01, 0x02, 0x26, 0x03, 0x58, 0x20])
        + CS
        + bytes([0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00])
    )
    print("seed_plaintext", seed_plaintext.hex())
    print("seed_credential_id", credential_id(seed_plaintext, k_wrap).hex())

    # Device-only, discoverable: {1: 0, 2: -7, 4: 5, 5: tag, 6: 3, 7: true, 8: "user-1" bytes,
    # 9: "alice", 10: "Alice A", 11: 2, 12: 7}.
    slot_plaintext = (
        bytes([0xAB, 0x01, 0x00, 0x02, 0x26, 0x04, 0x05, 0x05, 0x50])
        + SLOT_TAG
        + bytes([0x06, 0x03, 0x07, 0xF5, 0x08, 0x46])
        + b"user-1"
        + bytes([0x09, 0x65])
        + b"alice"
        + bytes([0x0A, 0x67])
        + b"Alice A"
        + bytes([0x0B, 0x02, 0x0C, 0x07])
    )
    print("slot_plaintext", slot_plaintext.hex())
    print("slot_credential_id", credential_id(slot_plaintext, k_wrap).hex())

    # Device-only, non-discoverable, key under K_dev: {1: 0, 2: -7, 3: cs, 6: 1, 7: false, 11: 0}.
    device_plaintext = (
        bytes([0xA6, 0x01, 0x00, 0x02, 0x26, 0x03, 0x58, 0x20])
        + CS
        + bytes([0x06, 0x01, 0x07, 0xF4, 0x0B, 0x00])
    )
    print("device_plaintext", device_plaintext.hex())
    print("device_credential_id", credential_id(device_plaintext, k_wrap).hex())

    if len(sys.argv) == 3 and sys.argv[1] == "--seeds":
        seeds = [
            seed_plaintext,
            credential_id(seed_plaintext, k_wrap),
            slot_plaintext,
            credential_id(slot_plaintext, k_wrap),
            device_plaintext,
            credential_id(device_plaintext, k_wrap),
        ]
        directory = Path(sys.argv[2])
        directory.mkdir(parents=True, exist_ok=True)
        for data in seeds:
            (directory / hashlib.sha1(data).hexdigest()).write_bytes(data)


if __name__ == "__main__":
    main()

import hashlib

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptoplay import hashing, signatures, symmetric


def test_sha384_matches_hashlib(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world" * 10000)
    assert hashing.sha384_file(f) == hashlib.sha384(f.read_bytes()).hexdigest()


def test_encrypt_decrypt_roundtrip():
    key = AESGCM.generate_key(bit_length=256)
    assert symmetric.decrypt(key, symmetric.encrypt(key, b"secret")) == b"secret"


def test_same_plaintext_gives_different_ciphertext():
    key = AESGCM.generate_key(bit_length=256)
    assert symmetric.encrypt(key, b"x") != symmetric.encrypt(key, b"x")  # fresh nonce


def test_tampered_ciphertext_is_rejected():
    key = AESGCM.generate_key(bit_length=256)
    blob = bytearray(symmetric.encrypt(key, b"secret"))
    blob[-1] ^= 0x01  # flip one bit of the tag
    with pytest.raises(InvalidTag):
        symmetric.decrypt(key, bytes(blob))


def test_wrong_key_is_rejected():
    blob = symmetric.encrypt(AESGCM.generate_key(bit_length=256), b"secret")
    with pytest.raises(InvalidTag):
        symmetric.decrypt(AESGCM.generate_key(bit_length=256), blob)


def test_signature_valid_and_invalid():
    sk = Ed25519PrivateKey.generate()
    sig = signatures.sign(sk, b"message")
    assert signatures.verify(sk.public_key(), b"message", sig)
    assert not signatures.verify(sk.public_key(), b"messagE", sig)  # changed data
    assert not signatures.verify(Ed25519PrivateKey.generate().public_key(), b"message", sig)  # wrong key

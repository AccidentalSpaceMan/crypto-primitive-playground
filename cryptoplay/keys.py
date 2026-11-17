"""Randomness family: every key comes from the OS's secure random number generator."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key(path):
    """Write a random 256-bit AES key (32 raw bytes) to a file."""
    key = AESGCM.generate_key(bit_length=256)
    with open(path, "wb") as f:
        f.write(key)


def load_aes_key(path):
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError(f"{path} is {len(key)} bytes; an AES-256 key must be 32")
    return key


def generate_ed25519_keypair(priv_path, pub_path):
    """Write an Ed25519 private key and its public key as PEM files.

    The private key is NOT password-protected, to keep the demo simple.
    Real code would use serialization.BestAvailableEncryption(password).
    """
    sk = Ed25519PrivateKey.generate()
    with open(priv_path, "wb") as f:
        f.write(sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(pub_path, "wb") as f:
        f.write(sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

"""Randomness family: every key comes from the OS's secure random number generator."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyFileError(ValueError):
    """A key file exists but isn't the kind of key that was expected."""


def generate_aes_key(path):
    """Write a random 256-bit AES key (32 raw bytes) to a file."""
    key = AESGCM.generate_key(bit_length=256)
    with open(path, "wb") as f:
        f.write(key)


def load_aes_key(path):
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        hint = " (that looks like a PEM signing key, not an AES key)" if key.startswith(b"-----BEGIN") else ""
        raise KeyFileError(
            f"{path} is not an AES-256 key: it is {len(key)} bytes, but an AES-256 key "
            f"must be exactly 32{hint}. Create one with: keygen --type aes --out <file>"
        )
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
        data = f.read()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        if b"PUBLIC KEY" in data:
            raise KeyFileError(f"{path} is a public key. Signing needs the private key "
                               f"(the .pem file without .pub).") from None
        raise KeyFileError(f"{path} is not a valid private key file.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyFileError(f"{path} is a private key, but not an Ed25519 key.")
    return key


def load_public_key(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        if b"PRIVATE KEY" in data:
            raise KeyFileError(f"{path} is a private key. Verifying needs the public key "
                               f"(the .pub.pem file). Never share your private key.") from None
        raise KeyFileError(f"{path} is not a valid public key file.") from None
    if not isinstance(key, Ed25519PublicKey):
        raise KeyFileError(f"{path} is a public key, but not an Ed25519 key.")
    return key

"""Randomness family: every key comes from the OS's secure random number generator.

Also loads and saves key files, with clear errors when the wrong kind of key is used.
"""
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyFileError(ValueError):
    """A key file exists but isn't the kind of key that was expected."""


# ---------------------------------------------------------------- PEM helpers

_PEM_BLOCK = re.compile(rb"-----BEGIN [A-Z ]+-----.+?-----END [A-Z ]+-----\s*", re.DOTALL)


def _pem_private(key):
    # NOT password-protected, to keep the demo simple. Real code would use
    # serialization.BestAvailableEncryption(password).
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem_public(key):
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _read_pem_keys(path, private):
    """Load every key in a PEM file (hybrid key files hold two).

    Raises KeyFileError if the file isn't PEM or holds the wrong kind
    (public vs private) of key.
    """
    with open(path, "rb") as f:
        data = f.read()
    blocks = _PEM_BLOCK.findall(data)
    if not blocks:
        kind = "private" if private else "public"
        raise KeyFileError(f"{path} is not a valid {kind} key file.")
    if private and all(b"PUBLIC KEY" in b for b in blocks):
        raise KeyFileError(f"{path} is a public key, but this needs the private key "
                           f"(the .pem file without .pub).")
    if not private and all(b"PRIVATE KEY" in b for b in blocks):
        raise KeyFileError(f"{path} is a private key, but this needs the public key "
                           f"(the .pub.pem file). Never share your private key.")
    try:
        if private:
            return [serialization.load_pem_private_key(b, password=None) for b in blocks]
        return [serialization.load_pem_public_key(b) for b in blocks]
    except (ValueError, TypeError):
        kind = "private" if private else "public"
        raise KeyFileError(f"{path} is not a valid {kind} key file.") from None


def _describe(keys):
    hybrid_types = (X25519PrivateKey, X25519PublicKey, MLKEM768PrivateKey, MLKEM768PublicKey)
    if any(isinstance(k, hybrid_types) for k in keys):
        return "a hybrid file-sharing key"
    if any(isinstance(k, (Ed25519PrivateKey, Ed25519PublicKey)) for k in keys):
        return "an Ed25519 signing key"
    return "a different kind of key"


# ---------------------------------------------------------------- AES keys

def generate_aes_key(path):
    """Write a random 256-bit AES key (32 raw bytes) to a file."""
    _write(path, AESGCM.generate_key(bit_length=256))


def load_aes_key(path):
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        hint = " (that looks like a PEM key file, not an AES key)" if key.startswith(b"-----BEGIN") else ""
        raise KeyFileError(
            f"{path} is not an AES-256 key: it is {len(key)} bytes, but an AES-256 key "
            f"must be exactly 32{hint}. Create one with: keygen --type aes --out <file>"
        )
    return key


# ---------------------------------------------------------------- Ed25519 signing keys

def generate_ed25519_keypair(priv_path, pub_path):
    """Write an Ed25519 private key and its public key as PEM files."""
    sk = Ed25519PrivateKey.generate()
    _write(priv_path, _pem_private(sk))
    _write(pub_path, _pem_public(sk.public_key()))


def load_private_key(path):
    keys = _read_pem_keys(path, private=True)
    if len(keys) != 1 or not isinstance(keys[0], Ed25519PrivateKey):
        raise KeyFileError(f"{path} is {_describe(keys)}, but signing needs an Ed25519 "
                           f"private key. Create one with: keygen --type ed25519 --out <name>")
    return keys[0]


def load_public_key(path):
    keys = _read_pem_keys(path, private=False)
    if len(keys) != 1 or not isinstance(keys[0], Ed25519PublicKey):
        raise KeyFileError(f"{path} is {_describe(keys)}, but verifying needs an Ed25519 "
                           f"public key.")
    return keys[0]


# ---------------------------------------------------------------- hybrid file-sharing keys

def generate_hybrid_keypair(priv_path, pub_path):
    """Write a hybrid key pair: one X25519 key and one ML-KEM-768 key per file.

    Each file simply holds two PEM blocks, one per algorithm.
    """
    x_sk = X25519PrivateKey.generate()
    m_sk = MLKEM768PrivateKey.generate()
    _write(priv_path, _pem_private(x_sk) + _pem_private(m_sk))
    _write(pub_path, _pem_public(x_sk.public_key()) + _pem_public(m_sk.public_key()))


def _pick_hybrid(path, keys, x_type, m_type, needed):
    x = [k for k in keys if isinstance(k, x_type)]
    m = [k for k in keys if isinstance(k, m_type)]
    if len(keys) != 2 or len(x) != 1 or len(m) != 1:
        raise KeyFileError(f"{path} is {_describe(keys)}, but {needed}. "
                           f"Create one with: keygen --type hybrid --out <name>")
    return x[0], m[0]


def load_hybrid_private_key(path):
    """Return (X25519PrivateKey, MLKEM768PrivateKey)."""
    keys = _read_pem_keys(path, private=True)
    return _pick_hybrid(path, keys, X25519PrivateKey, MLKEM768PrivateKey,
                        "unsealing needs a hybrid X25519 + ML-KEM-768 private key")


def load_hybrid_public_key(path):
    """Return (X25519PublicKey, MLKEM768PublicKey)."""
    keys = _read_pem_keys(path, private=False)
    return _pick_hybrid(path, keys, X25519PublicKey, MLKEM768PublicKey,
                        "sealing needs a hybrid X25519 + ML-KEM-768 public key")

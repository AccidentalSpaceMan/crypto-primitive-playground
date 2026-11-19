"""Randomness family: every key comes from the OS's secure random number generator.

Also loads and saves key files, with clear errors when the wrong kind of key is used.
"""
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
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
    def has(*types):
        return any(isinstance(k, types) for k in keys)

    if has(X25519PrivateKey, X25519PublicKey, MLKEM768PrivateKey, MLKEM768PublicKey):
        return "a hybrid file-sharing key"
    ed = has(Ed25519PrivateKey, Ed25519PublicKey)
    ml = has(MLDSA65PrivateKey, MLDSA65PublicKey)
    if ed and ml:
        return "a hybrid signing key"
    if ed:
        return "an Ed25519 signing key"
    if ml:
        return "an ML-DSA signing key"
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


# ---------------------------------------------------------------- signing keys
#
# Three kinds, each saved as PEM:
#   ed25519      one Ed25519 key           (classical)
#   mldsa        one ML-DSA-65 key         (post-quantum, FIPS 204)
#   hybrid-sign  Ed25519 + ML-DSA-65 keys  (two PEM blocks in one file)

_SIGNING_TYPES = "ed25519, mldsa or hybrid-sign"


def _generate_signing_keys(kind):
    if kind == "ed25519":
        return [Ed25519PrivateKey.generate()]
    if kind == "mldsa":
        return [MLDSA65PrivateKey.generate()]
    if kind == "hybrid-sign":
        return [Ed25519PrivateKey.generate(), MLDSA65PrivateKey.generate()]
    raise ValueError(f"unknown signing key type: {kind}")


def generate_signing_keypair(kind, priv_path, pub_path):
    """Write a signing key pair of the given kind (see above) as PEM files."""
    sks = _generate_signing_keys(kind)
    _write(priv_path, b"".join(_pem_private(sk) for sk in sks))
    _write(pub_path, b"".join(_pem_public(sk.public_key()) for sk in sks))


def generate_ed25519_keypair(priv_path, pub_path):
    generate_signing_keypair("ed25519", priv_path, pub_path)


def _pick_signing(path, keys, ed_type, ml_type, action):
    """Return a single key (Ed25519 or ML-DSA) or an (Ed25519, ML-DSA) tuple."""
    ed = [k for k in keys if isinstance(k, ed_type)]
    ml = [k for k in keys if isinstance(k, ml_type)]
    if len(ed) + len(ml) == len(keys):
        if len(keys) == 1:
            return keys[0]
        if len(ed) == 1 and len(ml) == 1:
            return ed[0], ml[0]
    raise KeyFileError(f"{path} is {_describe(keys)}, but {action} needs a signing key "
                       f"({_SIGNING_TYPES}). Create one with: keygen --type ed25519 --out <name>")


def load_private_key(path):
    """Load a signing private key: Ed25519, ML-DSA-65, or an (Ed25519, ML-DSA-65) pair."""
    keys = _read_pem_keys(path, private=True)
    return _pick_signing(path, keys, Ed25519PrivateKey, MLDSA65PrivateKey, "signing")


def load_public_key(path):
    """Load a verifying public key: Ed25519, ML-DSA-65, or an (Ed25519, ML-DSA-65) pair."""
    keys = _read_pem_keys(path, private=False)
    return _pick_signing(path, keys, Ed25519PublicKey, MLDSA65PublicKey, "verifying")


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

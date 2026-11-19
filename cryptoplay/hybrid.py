"""Key exchange + public-key encryption + KDF families:
hybrid X25519 + ML-KEM-768, combined with HKDF-SHA-384, then AES-256-GCM.

Goal: encrypt ("seal") a file to someone's PUBLIC key, so only their private
key can open it. No shared secret has to be sent ahead of time.

Why two algorithms ("hybrid")?
  * X25519 is classical elliptic-curve key exchange. Well studied, but a large
    quantum computer running Shor's algorithm would break it.
  * ML-KEM-768 (FIPS 203) is post-quantum: built on lattice math that Shor's
    algorithm doesn't break, but it is much newer.
  * We derive the file key from BOTH shared secrets, so the file stays safe as
    long as EITHER algorithm holds. This is the same idea as X25519MLKEM768 in
    TLS 1.3 (Chrome, Firefox, Cloudflare, Signal, iMessage PQ3).

How sealing works:
  1. Make a throwaway ("ephemeral") X25519 key pair and do key exchange with the
     recipient's X25519 public key            -> shared secret #1
  2. ML-KEM-encapsulate to the recipient's ML-KEM public key
                                               -> shared secret #2 + ciphertext
  3. HKDF-SHA-384(secret #2 || secret #1) -> one 32-byte AES-256 key
  4. AES-256-GCM encrypt the file with that key.

Sealed file layout:

  | "CPH1" (4) | ephemeral X25519 public key (32) | ML-KEM-768 ciphertext (1088) |
  | nonce (12) | ciphertext | tag (16) |

The first 1124 bytes (the header) are authenticated as AES-GCM associated data,
so changing any part of the file is detected.

Note: sealing proves nothing about WHO sent the file, since anyone with your
public key can seal to you. To prove the sender, also sign the file.
"""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import symmetric

MAGIC = b"CPH1"  # marks a hybrid-sealed file, version 1
X25519_PUB_SIZE = 32
MLKEM768_CT_SIZE = 1088
HEADER_SIZE = len(MAGIC) + X25519_PUB_SIZE + MLKEM768_CT_SIZE  # 1124
MIN_SIZE = HEADER_SIZE + symmetric.NONCE_SIZE + 16  # header + nonce + tag (empty file)

# HKDF "info" label: ties the derived key to this exact scheme and version.
LABEL = b"cryptoplay hybrid X25519+ML-KEM-768 v1"


def _derive_key(mlkem_secret, x25519_secret, eph_x_pub, recipient_x_pub):
    """KDF family: HKDF-SHA-384 turns the two shared secrets into one AES key.

    The X25519 public keys go into `info`, binding the key to this particular
    exchange.
    """
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=LABEL + eph_x_pub + recipient_x_pub,
    ).derive(mlkem_secret + x25519_secret)


def is_sealed_file(blob):
    return blob.startswith(MAGIC)


def seal(recipient_public, plaintext):
    """Encrypt plaintext to a (X25519PublicKey, MLKEM768PublicKey) pair."""
    x_pub, m_pub = recipient_public

    # 1. Classical key exchange with a fresh, single-use key pair.
    eph = X25519PrivateKey.generate()
    x25519_secret = eph.exchange(x_pub)
    eph_x_pub = eph.public_key().public_bytes_raw()

    # 2. Post-quantum key encapsulation.
    mlkem_secret, mlkem_ct = m_pub.encapsulate()

    # 3. Combine both secrets into one key.
    key = _derive_key(mlkem_secret, x25519_secret, eph_x_pub, x_pub.public_bytes_raw())

    # 4. Encrypt, authenticating the header too.
    header = MAGIC + eph_x_pub + mlkem_ct
    return header + symmetric.encrypt(key, plaintext, aad=header)


def unseal(recipient_private, blob):
    """Decrypt a sealed file with a (X25519PrivateKey, MLKEM768PrivateKey) pair.

    Raises ValueError if blob isn't a sealed file, or InvalidTag if the file was
    sealed to a different key or was modified.
    """
    if not is_sealed_file(blob):
        raise ValueError("not a sealed file")
    if len(blob) < MIN_SIZE:
        raise InvalidTag()  # truncated, so it was modified

    x_priv, m_priv = recipient_private
    header, rest = blob[:HEADER_SIZE], blob[HEADER_SIZE:]
    eph_x_pub = header[len(MAGIC):len(MAGIC) + X25519_PUB_SIZE]
    mlkem_ct = header[len(MAGIC) + X25519_PUB_SIZE:]

    try:
        x25519_secret = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_x_pub))
    except ValueError:
        raise InvalidTag() from None  # a tampered ephemeral key can be invalid

    # A wrong key or tampered ciphertext gives a different (random-looking)
    # secret instead of an error, so AES-GCM's tag check below catches it.
    mlkem_secret = m_priv.decapsulate(mlkem_ct)

    key = _derive_key(mlkem_secret, x25519_secret, eph_x_pub,
                      x_priv.public_key().public_bytes_raw())
    return symmetric.decrypt(key, rest, aad=header)

"""Key derivation family: turn a human password into an AES-256 key with Scrypt.

Passwords are short and guessable; AES keys must be 32 random-looking bytes.
A key derivation function (KDF) bridges the gap:

  * A random **salt** is mixed in, so the same password gives a different key
    in every file. Attackers can't precompute a table of password -> key.
  * Scrypt is deliberately **slow and memory-hungry** (about 1 second and
    128 MB here). One guess is cheap for you, but billions of guesses are very
    expensive for an attacker.

Password-encrypted file layout:

  | "CPW1" (4 bytes) | salt (16 bytes) | nonce (12) | ciphertext | tag (16) |

The 20-byte header (magic + salt) is passed to AES-GCM as associated data, so
changing it is detected just like changing the ciphertext.
"""
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import symmetric

MAGIC = b"CPW1"  # marks a password-encrypted file, version 1
SALT_SIZE = 16   # 128-bit random salt

# Scrypt cost settings (OWASP-recommended minimum): N = 2^17, r = 8, p = 1.
# Memory used is about 128 * N * r bytes = 128 MB.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(password, salt):
    """Derive a 32-byte AES-256 key from a password string and a salt."""
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def is_password_file(blob):
    return blob.startswith(MAGIC)


def encrypt_with_password(password, plaintext):
    salt = os.urandom(SALT_SIZE)
    header = MAGIC + salt
    key = derive_key(password, salt)
    return header + symmetric.encrypt(key, plaintext, aad=header)


def decrypt_with_password(password, blob):
    """Raises ValueError if blob isn't a password-encrypted file, or
    cryptography.exceptions.InvalidTag if the password is wrong or the file
    was modified."""
    if not is_password_file(blob):
        raise ValueError("not a password-encrypted file")
    header_len = len(MAGIC) + SALT_SIZE
    header, rest = blob[:header_len], blob[header_len:]
    salt = header[len(MAGIC):]
    key = derive_key(password, salt)
    return symmetric.decrypt(key, rest, aad=header)

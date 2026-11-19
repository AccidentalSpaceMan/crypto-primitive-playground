"""MAC family: HMAC-SHA-384.

A MAC (message authentication code) is a "keyed fingerprint". Like a hash it
detects any change to a file, but computing it needs a secret key. So:

  * A hash proves a file hasn't changed, but anyone can recompute it. An
    attacker who changes the file can just publish a new hash.
  * A MAC can only be made or checked by someone holding the shared key. An
    attacker without the key can't produce a valid tag for a changed file.
  * A signature also proves WHO made it, using public/private keys. Anyone can
    check it, but only the private-key holder can create it.

HMAC wraps a hash function (here SHA-384) in a construction proven secure as
long as the hash is. HMAC-SHA-384 is unaffected in practice by quantum
computers when used with a long key; this project uses 384-bit (48-byte) keys.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

KEY_SIZE = 48  # 384 bits, matching SHA-384's output size
TAG_SIZE = 48


def _hmac_file(key, path, chunk_size=65536):
    h = hmac.HMAC(key, hashes.SHA384())
    with open(path, "rb") as f:
        while block := f.read(chunk_size):
            h.update(block)
    return h


def tag_file(key, path):
    """Return the 48-byte HMAC-SHA-384 tag of a file, reading it in chunks."""
    return _hmac_file(key, path).finalize()


def verify_file(key, path, tag):
    """Return True if tag is the correct HMAC-SHA-384 tag for the file.

    Uses a constant-time comparison. A naive `==` can stop at the first wrong
    byte, and an attacker measuring how long that takes could guess a valid
    tag one byte at a time (a timing attack).
    """
    try:
        _hmac_file(key, path).verify(tag)
        return True
    except InvalidSignature:
        return False

"""Symmetric encryption + AEAD family: AES-256-GCM."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, the standard nonce size for GCM


def encrypt(key, plaintext, aad=b""):
    """Encrypt and authenticate. Output layout: nonce || ciphertext || 16-byte tag."""
    nonce = os.urandom(NONCE_SIZE)  # fresh every time; never reuse with the same key
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key, blob, aad=b""):
    """Check the tag, then decrypt.

    Raises cryptography.exceptions.InvalidTag if the key is wrong or if the
    nonce, ciphertext, tag or AAD was changed.
    """
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

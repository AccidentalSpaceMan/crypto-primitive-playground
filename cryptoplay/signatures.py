"""Digital signature family: Ed25519."""
from cryptography.exceptions import InvalidSignature


def sign(private_key, data):
    """Return a 64-byte Ed25519 signature over data."""
    return private_key.sign(data)


def verify(public_key, data, signature):
    """Return True if the signature is valid for data under public_key."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False

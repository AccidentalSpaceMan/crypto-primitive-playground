"""Digital signature family: Ed25519, ML-DSA-65, or both together (hybrid).

  * Ed25519 is classical elliptic-curve signing: tiny 64-byte signatures, but a
    large quantum computer running Shor's algorithm could forge them.
  * ML-DSA-65 (FIPS 204, formerly "Dilithium") is post-quantum, built on
    lattice math. Its signatures are 3,309 bytes.
  * Hybrid ("composite") signing uses BOTH. A signature is accepted only if both
    halves verify, so a forger has to break both algorithms.

Signature formats:
  Ed25519      | signature (64) |
  ML-DSA-65    | signature (3309) |
  hybrid       | "CPS1" (4) | Ed25519 signature (64) | ML-DSA-65 signature (3309) |

Stripping attacks: in a hybrid signature, an attacker might cut out one half
and present it as an ordinary single-algorithm signature (for example, keep
the Ed25519 half and forge it later with a quantum computer). To prevent this,
both halves sign under a hybrid-only label, so neither half is a valid
standalone signature on the same message:
  * Ed25519 signs LABEL + message.
  * ML-DSA signs the message with LABEL as its "context" string (a FIPS 204
    feature for exactly this kind of domain separation).
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

MAGIC = b"CPS1"  # marks a hybrid signature, version 1
LABEL = b"cryptoplay hybrid Ed25519+ML-DSA-65 v1"
ED25519_SIG_SIZE = 64
MLDSA65_SIG_SIZE = 3309
HYBRID_SIG_SIZE = len(MAGIC) + ED25519_SIG_SIZE + MLDSA65_SIG_SIZE  # 3377


def sign(private_key, data):
    """Sign data. private_key is an Ed25519 key, an ML-DSA-65 key, or an
    (Ed25519, ML-DSA-65) tuple for a hybrid signature."""
    if isinstance(private_key, tuple):
        ed, ml = private_key
        return MAGIC + ed.sign(LABEL + data) + ml.sign(data, LABEL)
    if isinstance(private_key, (Ed25519PrivateKey, MLDSA65PrivateKey)):
        return private_key.sign(data)
    raise TypeError(f"not a signing key: {type(private_key).__name__}")


def verify(public_key, data, signature):
    """Return True only if the signature is valid for data under public_key.

    For a hybrid key, BOTH halves must be valid.
    """
    try:
        if isinstance(public_key, tuple):
            ed, ml = public_key
            if len(signature) != HYBRID_SIG_SIZE or not signature.startswith(MAGIC):
                return False
            ed_sig = signature[len(MAGIC):len(MAGIC) + ED25519_SIG_SIZE]
            ml_sig = signature[len(MAGIC) + ED25519_SIG_SIZE:]
            ed.verify(ed_sig, LABEL + data)
            ml.verify(ml_sig, data, LABEL)
            return True
        if isinstance(public_key, (Ed25519PublicKey, MLDSA65PublicKey)):
            public_key.verify(signature, data)
            return True
    except InvalidSignature:
        return False
    raise TypeError(f"not a verifying key: {type(public_key).__name__}")

"""Hash function family: SHA-384."""
import hashlib


def sha384_file(path, chunk_size=65536):
    """Return the SHA-384 hex digest of a file, reading it in chunks."""
    h = hashlib.sha384()
    with open(path, "rb") as f:
        while block := f.read(chunk_size):
            h.update(block)
    return h.hexdigest()

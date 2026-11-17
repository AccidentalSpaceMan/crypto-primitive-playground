# Crypto Primitive Playground

A small Python CLI that demonstrates one cryptographic primitive per module: encrypt a file with
AES-256-GCM, hash it with SHA-384, sign it with Ed25519, and verify the signature.

Every primitive comes from the [`cryptography`](https://cryptography.io) library or Python's
`hashlib`. Nothing here implements crypto from scratch.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m cryptoplay.cli hash    demo.txt
python -m cryptoplay.cli keygen  --type aes --out aes.key
python -m cryptoplay.cli encrypt demo.txt --key aes.key -o demo.enc
python -m cryptoplay.cli decrypt demo.enc --key aes.key -o demo.out.txt
python -m cryptoplay.cli keygen  --type ed25519 --out me      # writes me.pem + me.pub.pem
python -m cryptoplay.cli sign    demo.txt --priv me.pem -o demo.sig
python -m cryptoplay.cli verify  demo.txt --pub me.pub.pem --sig demo.sig
```

## Function → primitive map

| Function | Primitive | Family | Security property |
|---|---|---|---|
| `hashing.sha384_file` | SHA-384 | Hash function | Integrity: any change gives a different digest |
| `symmetric.encrypt` / `decrypt` | AES-256 in GCM mode | Symmetric encryption | Confidentiality |
| GCM tag inside `symmetric.encrypt` / `decrypt` | GMAC (GHASH) | MAC / authenticated encryption (AEAD) | Detects tampering and wrong keys |
| `signatures.sign` / `verify` | Ed25519 | Digital signature (public-key) | Authenticity and non-repudiation |
| `keys.generate_aes_key`, `keys.generate_ed25519_keypair`, nonce in `symmetric.encrypt` | OS CSPRNG (`os.urandom`) | Secure randomness | Unpredictable keys and nonces |

## Encrypted file format

```
| nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes) |
```

## Limitations (this is a demo)

- Private keys and the AES key are stored unencrypted on disk. Real code would protect the private
  key with `BestAvailableEncryption(password)` and derive the AES key from a password with a KDF
  such as Scrypt.
- Files are read fully into memory, so very large files are not supported.
- A random 96-bit nonce is safe for about 2^32 encryptions under one key. Never reuse a nonce
  with the same key.

## Tests

```bash
python -m pytest -q
```

The tests check round-trips, that the same plaintext encrypts differently each time, that a
flipped bit or wrong key makes decryption fail, and that changed data or a wrong public key makes
signature verification fail.

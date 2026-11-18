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

# Or encrypt with a password instead of a key file (you'll be prompted)
python -m cryptoplay.cli encrypt demo.txt --password -o demo.enc
python -m cryptoplay.cli decrypt demo.enc --password -o demo.out.txt
```

## Function → primitive map

| Function | Primitive | Family | Security property |
|---|---|---|---|
| `hashing.sha384_file` | SHA-384 | Hash function | Integrity: any change gives a different digest |
| `symmetric.encrypt` / `decrypt` | AES-256 in GCM mode | Symmetric encryption | Confidentiality |
| GCM tag inside `symmetric.encrypt` / `decrypt` | GMAC (GHASH) | MAC / authenticated encryption (AEAD) | Detects tampering and wrong keys |
| `signatures.sign` / `verify` | Ed25519 | Digital signature (public-key) | Authenticity and non-repudiation |
| `keys.generate_aes_key`, `keys.generate_ed25519_keypair`, nonce in `symmetric.encrypt` | OS CSPRNG (`os.urandom`) | Secure randomness | Unpredictable keys and nonces |
| `kdf.derive_key` | Scrypt (N=2^17, r=8, p=1) | Key derivation function (KDF) | Turns a guessable password into a strong key; salted and slow to resist guessing |

## Encrypted file formats

Key-file mode (`--key`):

```
| nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes) |
```

Password mode (`--password`):

```
| "CPW1" (4) | salt (16) | nonce (12) | ciphertext | tag (16) |
```

The salt isn't secret. It is stored in the file so decryption can re-derive the same key. The
`CPW1` + salt header is authenticated as AES-GCM associated data, so tampering with it is detected.

## Error messages

Common mistakes print a single `Error: ...` line and exit with code 1 instead of a Python
traceback. These include a missing or misspelled file, a folder passed instead of a file, a public
key used for signing, a private key used for verifying, and a file that isn't an AES-256 key.
Pressing Ctrl+C at a password prompt exits with code 130. Unexpected bugs still show a full
traceback so they can be fixed.

## Limitations (this is a demo)

- Private keys and AES key files are stored unencrypted on disk. Real code would protect the
  private key with `BestAvailableEncryption(password)`. Password mode avoids the AES key file entirely.
- Password mode is only as strong as the password. Scrypt slows guessing down but can't save
  `password123`.
- Files are read fully into memory, so very large files are not supported.
- A random 96-bit nonce is safe for about 2^32 encryptions under one key. Never reuse a nonce
  with the same key.

## Tests

```bash
python -m pytest -q
```

The tests check round-trips, that the same plaintext encrypts differently each time, that a
flipped bit or wrong key makes decryption fail, and that changed data or a wrong public key makes
signature verification fail. Password tests also check that a wrong password, a tampered salt or a
mismatched confirmation is rejected, and that the same password gives a different file every time.
Error tests (`tests/test_errors.py`) check that each common mistake gives a clear message and no
traceback.

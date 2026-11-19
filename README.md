# Crypto Primitive Playground

[![Tests](https://github.com/AccidentalSpaceMan/crypto-primitive-playground/actions/workflows/tests.yml/badge.svg)](https://github.com/AccidentalSpaceMan/crypto-primitive-playground/actions/workflows/tests.yml)

A small Python CLI that demonstrates the major families of cryptographic primitives: hash a file
with SHA-384, encrypt it with AES-256-GCM, protect it with a password (scrypt), sign it with
Ed25519, and send it to someone using **hybrid post-quantum key exchange** (X25519 + ML-KEM-768).

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
# Hash
python -m cryptoplay.cli hash    demo.txt

# Encrypt with a shared key file...
python -m cryptoplay.cli keygen  --type aes --out aes.key
python -m cryptoplay.cli encrypt demo.txt --key aes.key -o demo.enc
python -m cryptoplay.cli decrypt demo.enc --key aes.key -o demo.out.txt

# ...or with a password (you'll be prompted)
python -m cryptoplay.cli encrypt demo.txt --password -o demo.enc
python -m cryptoplay.cli decrypt demo.enc --password -o demo.out.txt

# Sign and verify
python -m cryptoplay.cli keygen  --type ed25519 --out me      # writes me.pem + me.pub.pem
python -m cryptoplay.cli sign    demo.txt --priv me.pem -o demo.sig
python -m cryptoplay.cli verify  demo.txt --pub me.pub.pem --sig demo.sig

# Send a file to a friend: no shared secret needed, quantum-resistant key exchange
python -m cryptoplay.cli keygen  --type hybrid --out friend   # friend shares friend.pub.pem
python -m cryptoplay.cli seal    demo.txt --to friend.pub.pem -o demo.sealed
python -m cryptoplay.cli unseal  demo.sealed --priv friend.pem -o demo.out.txt
```

## The ten primitive families

Each family, what demonstrates it here, and how it holds up against a cryptographically relevant
quantum computer (CRQC).

| # | Family | Primitive used | Where | Quantum status |
|---|---|---|---|---|
| 1 | **Key exchange** | X25519 **+ ML-KEM-768** (FIPS 203), hybrid | `hybrid.seal` / `unseal` | ✅ Hybrid: safe if *either* holds. X25519 alone falls to Shor's algorithm. |
| 2 | **Public-key encryption** | KEM-based design: hybrid KEM → HKDF → AES-GCM | `hybrid.seal` / `unseal` | ✅ Post-quantum via ML-KEM |
| 3 | **Digital signature** | Ed25519 | `signatures.sign` / `verify` | ⚠️ Classical: falls to Shor. ML-DSA (FIPS 204) is the PQC replacement. |
| 4 | **Symmetric block cipher** | AES-256 | `symmetric.encrypt` / `decrypt` | ✅ Grover's algorithm cuts it to about 128-bit strength, which is still safe |
| 5 | **Stream cipher / AEAD** | AES-256-GCM | `symmetric.encrypt` / `decrypt` | ✅ |
| 6 | **Hash function** | SHA-384 | `hashing.sha384_file` | ✅ |
| 7 | **MAC** | GMAC tag inside AES-GCM | `symmetric` (via GCM) | ✅ (no standalone HMAC command yet) |
| 8 | **Key derivation (KDF)** | HKDF-SHA-384 | `hybrid._derive_key` | ✅ |
| 9 | **Password hashing** | scrypt (N=2^17, r=8, p=1), salted | `kdf.derive_key` | ✅ Memory-hard, which resists GPUs |
| 10 | **Random number generation** | OS CSPRNG (`os.urandom`) | all key, nonce and salt generation | ✅ |

## How `seal` works (hybrid post-quantum key exchange)

A quantum computer running Shor's algorithm would break X25519, and an attacker could **record
sealed files today and decrypt them later** ("harvest now, decrypt later"). ML-KEM-768 is built on
lattice math that Shor's algorithm doesn't break, but it is much newer than X25519. Using both
means a sealed file stays safe as long as **either** algorithm holds. TLS 1.3 uses the same idea
(X25519MLKEM768 in Chrome, Firefox and Cloudflare).

1. **X25519:** create a single-use key pair and do key exchange with the recipient's X25519 public
   key. This gives shared secret #1.
2. **ML-KEM-768:** encapsulate to the recipient's ML-KEM public key. This gives shared secret #2
   plus a 1088-byte ciphertext.
3. **HKDF-SHA-384** combines secret #2 and secret #1 into one 32-byte AES-256 key.
4. **AES-256-GCM** encrypts the file.

`seal` only needs the recipient's **public** key, so anyone can seal a file to you. That also means
sealing doesn't prove who sent it. To prove the sender, sign the file as well.

## File formats

Key-file mode (`encrypt --key`):

```
| nonce (12) | ciphertext | tag (16) |
```

Password mode (`encrypt --password`):

```
| "CPW1" (4) | salt (16) | nonce (12) | ciphertext | tag (16) |
```

Sealed (`seal`):

```
| "CPH1" (4) | ephemeral X25519 public key (32) | ML-KEM-768 ciphertext (1088) | nonce (12) | ciphertext | tag (16) |
```

Salts, ephemeral public keys and KEM ciphertexts aren't secret, so they are stored in the file. In
password and sealed files the header is authenticated as AES-GCM associated data, so changing any
byte of the file is detected.

Hybrid key files (`keygen --type hybrid`) hold two standard PEM blocks, one X25519 and one
ML-KEM-768.

## Error messages

Common mistakes print a single `Error: ...` line and exit with code 1 instead of a Python
traceback. These include a missing or misspelled file, a folder passed instead of a file, a public
key where a private key is needed (or the reverse), a signing key used for sealing, and a file that
isn't an AES-256 key. Pressing Ctrl+C at a password prompt exits with code 130. Unexpected bugs
still show a full traceback so they can be fixed.

## Limitations (this is a demo)

- Private keys and AES key files are stored unencrypted on disk. Real code would protect them with
  `BestAvailableEncryption(password)`.
- Ed25519 signatures are not quantum-resistant. ML-DSA would be the upgrade.
- Password mode is only as strong as the password. scrypt slows guessing down but can't save
  `password123`.
- Files are read fully into memory, so very large files are not supported.
- A random 96-bit nonce is safe for about 2^32 encryptions under one key. Never reuse a nonce
  with the same key.

## Tests

```bash
python -m pytest -q
```

The tests check round trips and the failure cases that matter: flipped bits, wrong keys, wrong
passwords, edited signed files, and mixed-up key types. Hybrid tests (`tests/test_hybrid.py`) also
check that tampering with **any** part of a sealed file is rejected, and that the key depends on
**both** halves: a wrong X25519 key **or** a wrong ML-KEM key alone breaks decryption. Error tests
(`tests/test_errors.py`) check that each common mistake gives a clear message and no traceback.

GitHub Actions ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)) runs the full suite
on every push to `main` and every pull request, on Python 3.10–3.13 (Linux) and Python 3.13
(Windows). The badge at the top shows the latest result.

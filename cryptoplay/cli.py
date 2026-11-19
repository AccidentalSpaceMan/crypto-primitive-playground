"""Command-line entry point: python -m cryptoplay.cli <command> ..."""
import argparse
import getpass
import sys

from cryptography.exceptions import InvalidTag

from . import hashing, hybrid, kdf, keys, mac, signatures, symmetric


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


SIGNING_NAMES = {
    "ed25519": "Ed25519",
    "mldsa": "ML-DSA-65",
    "hybrid-sign": "hybrid Ed25519 + ML-DSA-65",
}


def signing_name(key):
    if isinstance(key, tuple):
        return SIGNING_NAMES["hybrid-sign"]
    return SIGNING_NAMES["ed25519"] if "Ed25519" in type(key).__name__ else SIGNING_NAMES["mldsa"]


def cmd_keygen(args):
    if args.type == "aes":
        keys.generate_aes_key(args.out)
        print(f"Wrote AES-256 key to {args.out}")
    elif args.type == "mac":
        keys.generate_mac_key(args.out)
        print(f"Wrote HMAC-SHA-384 key to {args.out} (share it only with whoever checks your tags)")
    else:
        priv, pub = f"{args.out}.pem", f"{args.out}.pub.pem"
        if args.type == "hybrid":
            keys.generate_hybrid_keypair(priv, pub)
            print(f"Wrote hybrid X25519 + ML-KEM-768 private key to {priv} (keep secret)")
            print(f"Wrote hybrid public key to {pub} (share this so people can seal files to you)")
        else:
            keys.generate_signing_keypair(args.type, priv, pub)
            print(f"Wrote {SIGNING_NAMES[args.type]} private key to {priv} (keep secret)")
            print(f"Wrote {SIGNING_NAMES[args.type]} public key to {pub} (share this so people "
                  f"can verify your signatures)")


def cmd_hash(args):
    print(f"{hashing.sha384_file(args.file)}  {args.file}")


def cmd_mac(args):
    tag = mac.tag_file(keys.load_mac_key(args.key), args.file)
    print(f"{tag.hex()}  {args.file}")


def cmd_mac_verify(args):
    try:
        tag = bytes.fromhex(args.tag.strip())
    except ValueError:
        return error("--tag must be a hex string, like the output of the mac command.")
    if len(tag) != mac.TAG_SIZE:
        return error(f"--tag must be {mac.TAG_SIZE * 2} hex characters "
                     f"({mac.TAG_SIZE} bytes); got {len(tag) * 2}.")
    if mac.verify_file(keys.load_mac_key(args.key), args.file, tag):
        print("MAC VALID (HMAC-SHA-384)")
        return 0
    print("MAC INVALID: the file was changed, or the key is wrong.", file=sys.stderr)
    return 1


def ask_password(confirm):
    """Prompt without echoing, so the password never appears on screen or in
    shell history (unlike a --password=... command-line argument)."""
    password = getpass.getpass("Password: ")
    if not password:
        raise SystemExit("Error: password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise SystemExit("Error: passwords do not match.")
    return password


def cmd_encrypt(args):
    plaintext = read_bytes(args.file)
    if args.password:
        blob = kdf.encrypt_with_password(ask_password(confirm=True), plaintext)
    else:
        blob = symmetric.encrypt(keys.load_aes_key(args.key), plaintext)
    write_bytes(args.out, blob)
    print(f"Encrypted {args.file} -> {args.out}")


def cmd_decrypt(args):
    blob = read_bytes(args.file)
    if hybrid.is_sealed_file(blob):
        print("Error: this file was sealed to a public key; use unseal.", file=sys.stderr)
        return 1
    if args.password and not kdf.is_password_file(blob):
        print("Error: this file was encrypted with a key file; use --key.", file=sys.stderr)
        return 1
    if not args.password and kdf.is_password_file(blob):
        print("Error: this file was encrypted with a password; use --password.", file=sys.stderr)
        return 1
    try:
        if args.password:
            plaintext = kdf.decrypt_with_password(ask_password(confirm=False), blob)
        else:
            plaintext = symmetric.decrypt(keys.load_aes_key(args.key), blob)
    except InvalidTag:
        what = "password" if args.password else "key"
        print(f"Decryption FAILED: wrong {what}, or the file was modified.", file=sys.stderr)
        return 1
    write_bytes(args.out, plaintext)
    print(f"Decrypted {args.file} -> {args.out}")


def cmd_sign(args):
    sk = keys.load_private_key(args.priv)
    sig = signatures.sign(sk, read_bytes(args.file))
    write_bytes(args.out, sig)
    print(f"Signed {args.file} -> {args.out} ({signing_name(sk)}, {len(sig)}-byte signature)")


def cmd_verify(args):
    pk = keys.load_public_key(args.pub)
    if signatures.verify(pk, read_bytes(args.file), read_bytes(args.sig)):
        print(f"Signature VALID ({signing_name(pk)})")
        return 0
    print("Signature INVALID", file=sys.stderr)
    return 1


def cmd_seal(args):
    recipient = keys.load_hybrid_public_key(args.to)
    write_bytes(args.out, hybrid.seal(recipient, read_bytes(args.file)))
    print(f"Sealed {args.file} -> {args.out} (only the private key matching {args.to} can open it)")


def cmd_unseal(args):
    blob = read_bytes(args.file)
    if not hybrid.is_sealed_file(blob):
        print("Error: this isn't a sealed file. Files made with encrypt are opened "
              "with decrypt.", file=sys.stderr)
        return 1
    private = keys.load_hybrid_private_key(args.priv)
    try:
        plaintext = hybrid.unseal(private, blob)
    except InvalidTag:
        print("Unseal FAILED: the file was sealed to a different key, or it was modified.",
              file=sys.stderr)
        return 1
    write_bytes(args.out, plaintext)
    print(f"Unsealed {args.file} -> {args.out}")


def build_parser():
    p = argparse.ArgumentParser(prog="cryptoplay", description="Crypto primitive playground")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("keygen", help="generate a key or key pair",
                       description="Key types: aes (shared AES-256 key); mac (shared "
                                   "HMAC-SHA-384 key); ed25519, mldsa, "
                                   "hybrid-sign (signing key pairs: classical, post-quantum, "
                                   "or both); hybrid (X25519 + ML-KEM-768 file-sharing key pair)")
    s.add_argument("--type", choices=["aes", "mac", "ed25519", "mldsa", "hybrid-sign", "hybrid"],
                   required=True)
    s.add_argument("--out", required=True, help="output file (for Ed25519, a name prefix)")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("hash", help="SHA-384 digest of a file")
    s.add_argument("file")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("mac", help="HMAC-SHA-384 tag of a file (needs a shared key)")
    s.add_argument("file")
    s.add_argument("--key", required=True, help="HMAC key file (keygen --type mac)")
    s.set_defaults(func=cmd_mac)

    s = sub.add_parser("mac-verify", help="check a file's HMAC-SHA-384 tag")
    s.add_argument("file")
    s.add_argument("--key", required=True, help="HMAC key file")
    s.add_argument("--tag", required=True, help="the hex tag printed by the mac command")
    s.set_defaults(func=cmd_mac_verify)

    for name, func, helptext in [
        ("encrypt", cmd_encrypt, "AES-256-GCM encrypt a file"),
        ("decrypt", cmd_decrypt, "AES-256-GCM decrypt a file"),
    ]:
        s = sub.add_parser(name, help=helptext)
        s.add_argument("file")
        source = s.add_mutually_exclusive_group(required=True)
        source.add_argument("--key", help="AES-256 key file")
        source.add_argument("--password", action="store_true",
                            help="prompt for a password and derive the key with Scrypt")
        s.add_argument("-o", "--out", required=True)
        s.set_defaults(func=func)

    s = sub.add_parser("sign", help="Ed25519 sign a file")
    s.add_argument("file")
    s.add_argument("--priv", required=True)
    s.add_argument("-o", "--out", required=True)
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="verify an Ed25519 signature")
    s.add_argument("file")
    s.add_argument("--pub", required=True)
    s.add_argument("--sig", required=True)
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("seal", help="encrypt a file to someone's hybrid public key "
                                    "(X25519 + ML-KEM-768)")
    s.add_argument("file")
    s.add_argument("--to", required=True, help="recipient's hybrid public key (.pub.pem)")
    s.add_argument("-o", "--out", required=True)
    s.set_defaults(func=cmd_seal)

    s = sub.add_parser("unseal", help="decrypt a sealed file with your hybrid private key")
    s.add_argument("file")
    s.add_argument("--priv", required=True, help="your hybrid private key (.pem)")
    s.add_argument("-o", "--out", required=True)
    s.set_defaults(func=cmd_unseal)
    return p


def error(message, code=1):
    print(f"Error: {message}", file=sys.stderr)
    return code


def main(argv=None):
    args = build_parser().parse_args(argv)
    # Turn expected problems (typos, wrong key files, missing folders) into one
    # clear line instead of a Python traceback. Real bugs still show a traceback.
    try:
        return args.func(args) or 0
    except FileNotFoundError as e:
        return error(f"file or folder not found: {e.filename}")
    except IsADirectoryError as e:
        return error(f"{e.filename} is a folder, not a file.")
    except PermissionError as e:
        return error(f"permission denied: {e.filename} "
                     f"(is it a folder, or open in another program?)")
    except OSError as e:
        return error(f"could not access {e.filename}: {e.strerror}")
    except keys.KeyFileError as e:
        return error(str(e))
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return error("cancelled.", code=130)


if __name__ == "__main__":
    sys.exit(main())

"""Command-line entry point: python -m cryptoplay.cli <command> ..."""
import argparse
import getpass
import sys

from cryptography.exceptions import InvalidTag

from . import hashing, kdf, keys, signatures, symmetric


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def cmd_keygen(args):
    if args.type == "aes":
        keys.generate_aes_key(args.out)
        print(f"Wrote AES-256 key to {args.out}")
    else:
        priv, pub = f"{args.out}.pem", f"{args.out}.pub.pem"
        keys.generate_ed25519_keypair(priv, pub)
        print(f"Wrote private key to {priv} and public key to {pub}")


def cmd_hash(args):
    print(f"{hashing.sha384_file(args.file)}  {args.file}")


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
    write_bytes(args.out, signatures.sign(sk, read_bytes(args.file)))
    print(f"Signed {args.file} -> {args.out}")


def cmd_verify(args):
    pk = keys.load_public_key(args.pub)
    if signatures.verify(pk, read_bytes(args.file), read_bytes(args.sig)):
        print("Signature VALID")
        return 0
    print("Signature INVALID", file=sys.stderr)
    return 1


def build_parser():
    p = argparse.ArgumentParser(prog="cryptoplay", description="Crypto primitive playground")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("keygen", help="generate an AES key or an Ed25519 key pair")
    s.add_argument("--type", choices=["aes", "ed25519"], required=True)
    s.add_argument("--out", required=True, help="output file (for Ed25519, a name prefix)")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("hash", help="SHA-384 digest of a file")
    s.add_argument("file")
    s.set_defaults(func=cmd_hash)

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

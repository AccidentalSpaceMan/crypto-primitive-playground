"""Command-line entry point: python -m cryptoplay.cli <command> ..."""
import argparse
import sys

from cryptography.exceptions import InvalidTag

from . import hashing, keys, signatures, symmetric


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


def cmd_encrypt(args):
    key = keys.load_aes_key(args.key)
    write_bytes(args.out, symmetric.encrypt(key, read_bytes(args.file)))
    print(f"Encrypted {args.file} -> {args.out}")


def cmd_decrypt(args):
    key = keys.load_aes_key(args.key)
    try:
        plaintext = symmetric.decrypt(key, read_bytes(args.file))
    except InvalidTag:
        print("Decryption FAILED: wrong key, or the file was modified.", file=sys.stderr)
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
        s.add_argument("--key", required=True)
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


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())

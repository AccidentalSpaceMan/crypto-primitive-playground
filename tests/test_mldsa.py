import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from cryptoplay import cli, keys, signatures


def ed():
    return Ed25519PrivateKey.generate()


def ml():
    return MLDSA65PrivateKey.generate()


def pub(sk):
    return tuple(k.public_key() for k in sk) if isinstance(sk, tuple) else sk.public_key()


KINDS = {
    "ed25519": lambda: ed(),
    "mldsa": lambda: ml(),
    "hybrid-sign": lambda: (ed(), ml()),
}


# ---------------------------------------------------------------- every kind of signing key

@pytest.mark.parametrize("kind", KINDS)
def test_valid_signature(kind):
    sk = KINDS[kind]()
    assert signatures.verify(pub(sk), b"message", signatures.sign(sk, b"message"))


@pytest.mark.parametrize("kind", KINDS)
def test_changed_message_is_rejected(kind):
    sk = KINDS[kind]()
    assert not signatures.verify(pub(sk), b"messagE", signatures.sign(sk, b"message"))


@pytest.mark.parametrize("kind", KINDS)
def test_wrong_public_key_is_rejected(kind):
    sig = signatures.sign(KINDS[kind](), b"message")
    assert not signatures.verify(pub(KINDS[kind]()), b"message", sig)


@pytest.mark.parametrize("kind", KINDS)
def test_flipped_bit_in_signature_is_rejected(kind):
    sk = KINDS[kind]()
    sig = bytearray(signatures.sign(sk, b"message"))
    sig[len(sig) // 2] ^= 0x01
    assert not signatures.verify(pub(sk), b"message", bytes(sig))


@pytest.mark.parametrize("kind, size", [("ed25519", 64), ("mldsa", 3309), ("hybrid-sign", 3377)])
def test_signature_sizes(kind, size):
    assert len(signatures.sign(KINDS[kind](), b"m")) == size


# ---------------------------------------------------------------- hybrid: both halves required

def test_hybrid_needs_the_ed25519_half():
    e, m = ed(), ml()
    sig = bytearray(signatures.sign((e, m), b"msg"))
    sig[10] ^= 0x01  # inside the Ed25519 half; ML-DSA half still valid
    assert not signatures.verify((e.public_key(), m.public_key()), b"msg", bytes(sig))


def test_hybrid_needs_the_mldsa_half():
    e, m = ed(), ml()
    sig = bytearray(signatures.sign((e, m), b"msg"))
    sig[-10] ^= 0x01  # inside the ML-DSA half; Ed25519 half still valid
    assert not signatures.verify((e.public_key(), m.public_key()), b"msg", bytes(sig))


def test_hybrid_rejects_swapped_component_key():
    e, m = ed(), ml()
    sig = signatures.sign((e, m), b"msg")
    assert not signatures.verify((ed().public_key(), m.public_key()), b"msg", sig)
    assert not signatures.verify((e.public_key(), ml().public_key()), b"msg", sig)


# ---------------------------------------------------------------- stripping attacks

def test_ed25519_half_is_not_a_standalone_signature():
    """Cutting the Ed25519 half out of a hybrid signature must NOT give a valid
    plain Ed25519 signature, or a quantum attacker could forge just that half."""
    e, m = ed(), ml()
    sig = signatures.sign((e, m), b"msg")
    ed_half = sig[4:4 + 64]
    assert not signatures.verify(e.public_key(), b"msg", ed_half)


def test_mldsa_half_is_not_a_standalone_signature():
    e, m = ed(), ml()
    sig = signatures.sign((e, m), b"msg")
    ml_half = sig[4 + 64:]
    assert not signatures.verify(m.public_key(), b"msg", ml_half)


def test_plain_signatures_dont_combine_into_a_hybrid():
    """Gluing two ordinary signatures together must not pass as a hybrid one."""
    e, m = ed(), ml()
    glued = signatures.MAGIC + e.sign(b"msg") + m.sign(b"msg")
    assert not signatures.verify((e.public_key(), m.public_key()), b"msg", glued)


def test_single_key_rejects_hybrid_signature_and_vice_versa():
    e, m = ed(), ml()
    hybrid_sig = signatures.sign((e, m), b"msg")
    assert not signatures.verify(e.public_key(), b"msg", hybrid_sig)
    assert not signatures.verify(m.public_key(), b"msg", hybrid_sig)
    assert not signatures.verify((e.public_key(), m.public_key()), b"msg", e.sign(b"msg"))


# ---------------------------------------------------------------- key files

@pytest.mark.parametrize("kind", KINDS)
def test_key_files_roundtrip(tmp_path, kind):
    keys.generate_signing_keypair(kind, tmp_path / "k.pem", tmp_path / "k.pub.pem")
    sk = keys.load_private_key(tmp_path / "k.pem")
    pk = keys.load_public_key(tmp_path / "k.pub.pem")
    assert signatures.verify(pk, b"hi", signatures.sign(sk, b"hi"))


# ---------------------------------------------------------------- CLI

@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "doc.txt").write_bytes(b"release v1.0")
    for kind, name in [("mldsa", "pq"), ("hybrid-sign", "both"), ("ed25519", "classic"),
                       ("hybrid", "share")]:
        cli.main(["keygen", "--type", kind, "--out", str(tmp_path / name)])
    return tmp_path


def run(capsys, *args):
    code = cli.main([str(a) for a in args])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("name, label", [("pq", "ML-DSA-65"), ("both", "hybrid Ed25519 + ML-DSA-65"),
                                         ("classic", "Ed25519")])
def test_cli_sign_verify(workspace, capsys, name, label):
    w = workspace
    code, out, _ = run(capsys, "sign", w / "doc.txt", "--priv", w / f"{name}.pem", "-o", w / "doc.sig")
    assert code == 0 and label in out
    code, out, _ = run(capsys, "verify", w / "doc.txt", "--pub", w / f"{name}.pub.pem", "--sig", w / "doc.sig")
    assert code == 0 and "Signature VALID" in out and label in out


def test_cli_verify_with_wrong_kind_of_key(workspace, capsys):
    w = workspace
    run(capsys, "sign", w / "doc.txt", "--priv", w / "both.pem", "-o", w / "doc.sig")
    code, _, err = run(capsys, "verify", w / "doc.txt", "--pub", w / "classic.pub.pem", "--sig", w / "doc.sig")
    assert code == 1 and "Signature INVALID" in err


def test_cli_sharing_key_cannot_sign(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "sign", w / "doc.txt", "--priv", w / "share.pem", "-o", w / "x")
    assert code == 1 and "hybrid file-sharing key" in err and "hybrid-sign" in err


def test_cli_signing_key_cannot_seal(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "seal", w / "doc.txt", "--to", w / "both.pub.pem", "-o", w / "x")
    assert code == 1 and "hybrid signing key" in err

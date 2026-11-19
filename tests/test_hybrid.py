import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cryptoplay import cli, hybrid, keys


def make_keypair():
    x, m = X25519PrivateKey.generate(), MLKEM768PrivateKey.generate()
    return (x, m), (x.public_key(), m.public_key())


# ---------------------------------------------------------------- the scheme itself

def test_seal_unseal_roundtrip():
    priv, pub = make_keypair()
    assert hybrid.unseal(priv, hybrid.seal(pub, b"for your eyes only")) == b"for your eyes only"


def test_empty_file_roundtrip():
    priv, pub = make_keypair()
    assert hybrid.unseal(priv, hybrid.seal(pub, b"")) == b""


def test_sealed_layout():
    _, pub = make_keypair()
    blob = hybrid.seal(pub, b"12345")
    assert blob.startswith(b"CPH1")
    # header (4 + 32 + 1088) + nonce (12) + 5 bytes ciphertext + tag (16)
    assert len(blob) == 1124 + 12 + 5 + 16


def test_sealing_twice_gives_different_files():
    _, pub = make_keypair()
    assert hybrid.seal(pub, b"x") != hybrid.seal(pub, b"x")  # new ephemeral key + encapsulation


def test_wrong_recipient_is_rejected():
    _, pub = make_keypair()
    other_priv, _ = make_keypair()
    with pytest.raises(InvalidTag):
        hybrid.unseal(other_priv, hybrid.seal(pub, b"secret"))


@pytest.mark.parametrize("position, part", [
    (2, "magic is checked separately"),
    (10, "ephemeral X25519 public key"),
    (500, "ML-KEM ciphertext"),
    (1130, "AES-GCM nonce"),
    (-1, "AES-GCM tag"),
])
def test_tampering_anywhere_is_rejected(position, part):
    priv, pub = make_keypair()
    blob = bytearray(hybrid.seal(pub, b"secret"))
    blob[position] ^= 0x01
    with pytest.raises((InvalidTag, ValueError)):
        hybrid.unseal(priv, bytes(blob))


def test_truncated_file_is_rejected():
    priv, pub = make_keypair()
    with pytest.raises(InvalidTag):
        hybrid.unseal(priv, hybrid.seal(pub, b"secret")[:1000])


def test_each_half_matters():
    """Hybrid security: the key depends on BOTH shared secrets. Swapping in a
    different X25519 key OR a different ML-KEM key must break decryption."""
    (x, m), pub = make_keypair()
    blob = hybrid.seal(pub, b"secret")
    with pytest.raises(InvalidTag):
        hybrid.unseal((X25519PrivateKey.generate(), m), blob)  # right ML-KEM, wrong X25519
    with pytest.raises(InvalidTag):
        hybrid.unseal((x, MLKEM768PrivateKey.generate()), blob)  # right X25519, wrong ML-KEM


# ---------------------------------------------------------------- key files

def test_hybrid_key_files_roundtrip(tmp_path):
    keys.generate_hybrid_keypair(tmp_path / "k.pem", tmp_path / "k.pub.pem")
    priv = keys.load_hybrid_private_key(tmp_path / "k.pem")
    pub = keys.load_hybrid_public_key(tmp_path / "k.pub.pem")
    assert hybrid.unseal(priv, hybrid.seal(pub, b"hi")) == b"hi"


# ---------------------------------------------------------------- CLI

@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hello friend")
    for args in (["--type", "hybrid", "--out", "friend"],
                 ["--type", "hybrid", "--out", "stranger"],
                 ["--type", "ed25519", "--out", "signer"],
                 ["--type", "aes", "--out", "aes.key"]):
        args[-1] = str(tmp_path / args[-1])
        cli.main(["keygen", *args])
    return tmp_path


def run(capsys, *args):
    code = cli.main([str(a) for a in args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_seal_unseal(workspace, capsys):
    w = workspace
    assert run(capsys, "seal", w / "a.txt", "--to", w / "friend.pub.pem", "-o", w / "a.sealed")[0] == 0
    assert run(capsys, "unseal", w / "a.sealed", "--priv", w / "friend.pem", "-o", w / "out.txt")[0] == 0
    assert (w / "out.txt").read_bytes() == b"hello friend"


def test_cli_wrong_private_key(workspace, capsys):
    w = workspace
    run(capsys, "seal", w / "a.txt", "--to", w / "friend.pub.pem", "-o", w / "a.sealed")
    code, _, err = run(capsys, "unseal", w / "a.sealed", "--priv", w / "stranger.pem", "-o", w / "out.txt")
    assert code == 1 and "Unseal FAILED" in err
    assert not (w / "out.txt").exists()


def test_cli_signing_key_used_for_sealing(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "seal", w / "a.txt", "--to", w / "signer.pub.pem", "-o", w / "x")
    assert code == 1 and "Ed25519 signing key" in err and "keygen --type hybrid" in err


def test_cli_private_key_used_for_sealing(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "seal", w / "a.txt", "--to", w / "friend.pem", "-o", w / "x")
    assert code == 1 and "is a private key" in err


def test_cli_hybrid_key_used_for_signing(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "sign", w / "a.txt", "--priv", w / "friend.pem", "-o", w / "x")
    assert code == 1 and "hybrid file-sharing key" in err


def test_cli_unseal_a_non_sealed_file(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "unseal", w / "a.txt", "--priv", w / "friend.pem", "-o", w / "x")
    assert code == 1 and "isn't a sealed file" in err


def test_cli_decrypt_a_sealed_file(workspace, capsys):
    w = workspace
    run(capsys, "seal", w / "a.txt", "--to", w / "friend.pub.pem", "-o", w / "a.sealed")
    code, _, err = run(capsys, "decrypt", w / "a.sealed", "--key", w / "aes.key", "-o", w / "x")
    assert code == 1 and "use unseal" in err

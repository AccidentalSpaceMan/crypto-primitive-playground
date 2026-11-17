import pytest
from cryptography.exceptions import InvalidTag

from cryptoplay import cli, kdf


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Real settings take ~1 s per derivation; use a tiny cost in tests.
    (test_real_settings_work below still checks the real settings once.)"""
    monkeypatch.setattr(kdf, "SCRYPT_N", 2**10)


def test_same_password_and_salt_give_same_key():
    salt = b"s" * 16
    assert kdf.derive_key("hunter2", salt) == kdf.derive_key("hunter2", salt)


def test_different_salt_gives_different_key():
    assert kdf.derive_key("hunter2", b"a" * 16) != kdf.derive_key("hunter2", b"b" * 16)


def test_password_roundtrip():
    blob = kdf.encrypt_with_password("correct horse", b"secret")
    assert kdf.decrypt_with_password("correct horse", blob) == b"secret"


def test_same_password_twice_gives_different_files():
    # fresh salt (and nonce) every time
    assert kdf.encrypt_with_password("pw", b"x") != kdf.encrypt_with_password("pw", b"x")


def test_wrong_password_is_rejected():
    blob = kdf.encrypt_with_password("correct horse", b"secret")
    with pytest.raises(InvalidTag):
        kdf.decrypt_with_password("wrong horse", blob)


def test_tampered_salt_is_rejected():
    blob = bytearray(kdf.encrypt_with_password("pw", b"secret"))
    blob[len(kdf.MAGIC)] ^= 0x01  # flip a bit in the salt
    with pytest.raises(InvalidTag):
        kdf.decrypt_with_password("pw", bytes(blob))


def test_real_settings_work(monkeypatch):
    monkeypatch.setattr(kdf, "SCRYPT_N", 2**17)
    blob = kdf.encrypt_with_password("pw", b"secret")
    assert kdf.decrypt_with_password("pw", blob) == b"secret"


def test_cli_password_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "pw")
    src, enc, out = tmp_path / "a.txt", tmp_path / "a.enc", tmp_path / "b.txt"
    src.write_bytes(b"hello")
    assert cli.main(["encrypt", str(src), "--password", "-o", str(enc)]) == 0
    assert cli.main(["decrypt", str(enc), "--password", "-o", str(out)]) == 0
    assert out.read_bytes() == b"hello"


def test_cli_wrong_password_fails(tmp_path, monkeypatch):
    src, enc, out = tmp_path / "a.txt", tmp_path / "a.enc", tmp_path / "b.txt"
    src.write_bytes(b"hello")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "right")
    cli.main(["encrypt", str(src), "--password", "-o", str(enc)])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "wrong")
    assert cli.main(["decrypt", str(enc), "--password", "-o", str(out)]) == 1
    assert not out.exists()


def test_cli_mismatched_confirmation_fails(tmp_path, monkeypatch):
    answers = iter(["one", "two"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    src = tmp_path / "a.txt"
    src.write_bytes(b"hello")
    with pytest.raises(SystemExit):
        cli.main(["encrypt", str(src), "--password", "-o", str(tmp_path / "a.enc")])


def test_cli_key_and_password_cannot_be_combined(tmp_path):
    with pytest.raises(SystemExit):  # argparse rejects it
        cli.main(["encrypt", "x", "--key", "k", "--password", "-o", "y"])

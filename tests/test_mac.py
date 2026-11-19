import hashlib
import hmac as stdlib_hmac
import os

import pytest

from cryptoplay import cli, keys, mac


def test_rfc4231_known_answer(tmp_path):
    """RFC 4231 test case 2: a published HMAC-SHA-384 test vector, so this checks
    we get the standard answer and not just one our own code agrees with."""
    f = tmp_path / "msg"
    f.write_bytes(b"what do ya want for nothing?")
    expected = ("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47"
                "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
    assert mac.tag_file(b"Jefe", f).hex() == expected


def test_matches_python_stdlib_on_a_large_file(tmp_path):
    f = tmp_path / "big.bin"
    data = os.urandom(300_000)  # spans several 64 KB read chunks
    f.write_bytes(data)
    key = os.urandom(48)
    assert mac.tag_file(key, f) == stdlib_hmac.new(key, data, hashlib.sha384).digest()


def test_tag_is_48_bytes(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"x")
    assert len(mac.tag_file(os.urandom(48), f)) == 48


def test_valid_tag_verifies(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"pay Alice $10")
    key = os.urandom(48)
    assert mac.verify_file(key, f, mac.tag_file(key, f))


def test_changed_file_is_rejected(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"pay Alice $10")
    key = os.urandom(48)
    tag = mac.tag_file(key, f)
    f.write_bytes(b"pay Alice $99")
    assert not mac.verify_file(key, f, tag)


def test_wrong_key_is_rejected(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"pay Alice $10")
    tag = mac.tag_file(os.urandom(48), f)
    assert not mac.verify_file(os.urandom(48), f, tag)


def test_attacker_cannot_just_recompute(tmp_path):
    """The point of a MAC: unlike a plain hash, an attacker who edits the file
    can't make a matching tag without the key."""
    f = tmp_path / "a"
    f.write_bytes(b"pay Alice $10")
    key = os.urandom(48)
    f.write_bytes(b"pay Mallory $10")
    forged_hash = hashlib.sha384(f.read_bytes()).digest()  # same size as a tag
    assert not mac.verify_file(key, f, forged_hash)


def test_mac_key_file(tmp_path):
    keys.generate_mac_key(tmp_path / "m.key")
    assert len(keys.load_mac_key(tmp_path / "m.key")) == 48


def test_two_generated_keys_differ(tmp_path):
    keys.generate_mac_key(tmp_path / "a.key")
    keys.generate_mac_key(tmp_path / "b.key")
    assert (tmp_path / "a.key").read_bytes() != (tmp_path / "b.key").read_bytes()


# ---------------------------------------------------------------- CLI

@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "order.txt").write_bytes(b"ship 3 units")
    cli.main(["keygen", "--type", "mac", "--out", str(tmp_path / "mac.key")])
    cli.main(["keygen", "--type", "mac", "--out", str(tmp_path / "other.key")])
    cli.main(["keygen", "--type", "aes", "--out", str(tmp_path / "aes.key")])
    return tmp_path


def run(capsys, *args):
    code = cli.main([str(a) for a in args])
    out = capsys.readouterr()
    return code, out.out, out.err


def get_tag(capsys, w, key="mac.key"):
    code, out, _ = run(capsys, "mac", w / "order.txt", "--key", w / key)
    assert code == 0
    return out.split()[0]


def test_cli_mac_and_verify(workspace, capsys):
    w = workspace
    tag = get_tag(capsys, w)
    assert len(tag) == 96
    code, out, _ = run(capsys, "mac-verify", w / "order.txt", "--key", w / "mac.key", "--tag", tag)
    assert code == 0 and "MAC VALID" in out


def test_cli_changed_file(workspace, capsys):
    w = workspace
    tag = get_tag(capsys, w)
    (w / "order.txt").write_bytes(b"ship 300 units")
    code, _, err = run(capsys, "mac-verify", w / "order.txt", "--key", w / "mac.key", "--tag", tag)
    assert code == 1 and "MAC INVALID" in err


def test_cli_wrong_key(workspace, capsys):
    w = workspace
    tag = get_tag(capsys, w)
    code, _, err = run(capsys, "mac-verify", w / "order.txt", "--key", w / "other.key", "--tag", tag)
    assert code == 1 and "MAC INVALID" in err


def test_cli_aes_key_rejected_with_reuse_warning(workspace, capsys):
    w = workspace
    code, _, err = run(capsys, "mac", w / "order.txt", "--key", w / "aes.key")
    assert code == 1 and "looks like an AES key" in err and "keygen --type mac" in err


@pytest.mark.parametrize("bad_tag, message", [
    ("not-hex!", "must be a hex string"),
    ("abcd", "must be 96 hex characters"),
])
def test_cli_bad_tag_input(workspace, capsys, bad_tag, message):
    w = workspace
    code, _, err = run(capsys, "mac-verify", w / "order.txt", "--key", w / "mac.key", "--tag", bad_tag)
    assert code == 1 and message in err and "Traceback" not in err

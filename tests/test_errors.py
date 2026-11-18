"""Expected mistakes should print one 'Error: ...' line and exit 1, not crash."""
import pytest

from cryptoplay import cli


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hello")
    cli.main(["keygen", "--type", "ed25519", "--out", str(tmp_path / "me")])
    cli.main(["keygen", "--type", "aes", "--out", str(tmp_path / "aes.key")])
    return tmp_path


def run(capsys, *args):
    code = cli.main([str(a) for a in args])
    err = capsys.readouterr().err
    return code, err


def test_missing_input_file(workspace, capsys):
    code, err = run(capsys, "hash", workspace / "nope.txt")
    assert code == 1
    assert "Error: file or folder not found" in err and "nope.txt" in err
    assert "Traceback" not in err


def test_folder_instead_of_file(workspace, capsys):
    code, err = run(capsys, "hash", workspace)
    assert code == 1
    assert err.startswith("Error:")  # IsADirectoryError on Linux, PermissionError on Windows


def test_missing_output_folder(workspace, capsys):
    code, err = run(capsys, "encrypt", workspace / "a.txt", "--key", workspace / "aes.key",
                    "-o", workspace / "no_such_dir" / "a.enc")
    assert code == 1
    assert "not found" in err


def test_missing_key_file(workspace, capsys):
    code, err = run(capsys, "encrypt", workspace / "a.txt", "--key", workspace / "missing.key",
                    "-o", workspace / "a.enc")
    assert code == 1
    assert "missing.key" in err


def test_wrong_size_aes_key(workspace, capsys):
    code, err = run(capsys, "encrypt", workspace / "a.txt", "--key", workspace / "a.txt",
                    "-o", workspace / "a.enc")
    assert code == 1
    assert "not an AES-256 key" in err and "5 bytes" in err


def test_pem_file_used_as_aes_key(workspace, capsys):
    code, err = run(capsys, "encrypt", workspace / "a.txt", "--key", workspace / "me.pem",
                    "-o", workspace / "a.enc")
    assert code == 1
    assert "PEM signing key" in err


def test_public_key_used_for_signing(workspace, capsys):
    code, err = run(capsys, "sign", workspace / "a.txt", "--priv", workspace / "me.pub.pem",
                    "-o", workspace / "a.sig")
    assert code == 1
    assert "is a public key" in err


def test_private_key_used_for_verifying(workspace, capsys):
    run(capsys, "sign", workspace / "a.txt", "--priv", workspace / "me.pem", "-o", workspace / "a.sig")
    code, err = run(capsys, "verify", workspace / "a.txt", "--pub", workspace / "me.pem",
                    "--sig", workspace / "a.sig")
    assert code == 1
    assert "is a private key" in err


def test_garbage_key_file(workspace, capsys):
    code, err = run(capsys, "sign", workspace / "a.txt", "--priv", workspace / "a.txt",
                    "-o", workspace / "a.sig")
    assert code == 1
    assert "not a valid private key file" in err


def test_garbage_signature_file_is_just_invalid(workspace, capsys):
    code, err = run(capsys, "verify", workspace / "a.txt", "--pub", workspace / "me.pub.pem",
                    "--sig", workspace / "a.txt")
    assert code == 1
    assert "Signature INVALID" in err


def test_ctrl_c_at_password_prompt(workspace, capsys, monkeypatch):
    def interrupted(prompt=""):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli.getpass, "getpass", interrupted)
    code, err = run(capsys, "encrypt", workspace / "a.txt", "--password", "-o", workspace / "a.enc")
    assert code == 130
    assert "cancelled" in err

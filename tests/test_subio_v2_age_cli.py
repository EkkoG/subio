import subprocess
import sys

import pytest

from subio_v2.infrastructure import age


def run_age(*args, data=None):
    return subprocess.run([sys.executable, "-m", "subio_v2.main", "age", *map(str, args)],
                          input=data, capture_output=True, check=False)


@pytest.mark.parametrize("legacy", [False, True])
def test_identity_key_conversion_and_decryption(tmp_path, legacy):
    secret, public = age.generate_x25519_keypair()
    identity = tmp_path / "identity.txt"
    identity.write_text(f"# created for this test\n\n{secret}\n# end\n")
    identity.chmod(0o600)
    key_args = [secret] if legacy else ["--identity-file", identity]
    converted = run_age("convert", *key_args)
    assert converted.returncode == 0
    assert converted.stdout.decode().strip() == public
    assert secret.encode() not in converted.stdout + converted.stderr

    source = tmp_path / "source.age"
    target = tmp_path / "plaintext"
    plaintext = b"synthetic plaintext\n"
    source.write_bytes(age.encrypt_bytes(plaintext, public))
    decrypted = run_age("decrypt", *key_args, source, target)
    assert decrypted.returncode == 0, decrypted.stderr
    assert target.read_bytes() == plaintext
    assert secret.encode() not in decrypted.stdout + decrypted.stderr


def test_identity_decrypt_supports_stdin_and_default_stdout(tmp_path):
    secret, public = age.generate_x25519_keypair()
    identity = tmp_path / "identity"
    identity.write_text(secret)
    plaintext = b"\x00synthetic\xff\n"
    decrypted = run_age("decrypt", "--identity-file", identity, "-",
                        data=age.encrypt_bytes(plaintext, public))
    assert decrypted.returncode == 0
    assert decrypted.stdout == plaintext


@pytest.mark.parametrize("command", ["convert", "decrypt"])
@pytest.mark.parametrize("contents", ["", "# comment only\n", "PRIVATE_IDENTITY_CANARY",
                                     "PRIVATE_IDENTITY_CANARY\nSECOND_CANARY", "invalid-utf8"])
def test_bad_identity_file_does_not_echo_contents(tmp_path, command, contents):
    identity = tmp_path / "identity"
    identity.write_bytes(b"PRIVATE_IDENTITY_CANARY\xff" if contents == "invalid-utf8"
                         else contents.encode())
    result = run_age(command, "--identity-file", identity,
                     *(["-"] if command == "decrypt" else []), data=b"plaintext")
    assert result.returncode == 1
    assert b"PRIVATE_IDENTITY_CANARY" not in result.stdout + result.stderr
    assert b"SECOND_CANARY" not in result.stdout + result.stderr
    assert b"Traceback" not in result.stdout + result.stderr


@pytest.mark.parametrize("command", ["convert", "decrypt"])
def test_identity_file_read_error_is_safe(tmp_path, command):
    result = run_age(command, "--identity-file", tmp_path / "missing-PRIVATE_PATH_CANARY",
                     *(["-"] if command == "decrypt" else []))
    assert result.returncode == 1
    assert b"PRIVATE_PATH_CANARY" not in result.stdout + result.stderr


@pytest.mark.parametrize("arguments", [
    ("convert", "--identity-file", "identity", "PRIVATE_ARG_CANARY"),
    ("convert", "--unknown", "PRIVATE_ARG_CANARY"),
    ("decrypt", "--identity-file", "identity", "PRIVATE_ARG_CANARY", "source", "target"),
    ("decrypt", "--unknown", "PRIVATE_ARG_CANARY"),
    ("decrypt",), ("convert",),
])
def test_age_argument_errors_do_not_echo_values(arguments):
    result = run_age(*arguments)
    assert result.returncode == 2
    assert b"PRIVATE_ARG_CANARY" not in result.stdout + result.stderr


def test_legacy_invalid_key_error_is_safe():
    result = run_age("convert", "PRIVATE_KEY_CANARY")
    assert result.returncode == 1
    assert b"PRIVATE_KEY_CANARY" not in result.stdout + result.stderr

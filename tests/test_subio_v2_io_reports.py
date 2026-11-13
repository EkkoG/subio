import json
import sys
from pathlib import Path

import pytest

from subio_v2.main import main
from tests.test_subio_v2_check import _write_config


@pytest.mark.parametrize("command", [["check"], ["inspect", "providers"], ["inspect", "artifacts"]])
@pytest.mark.parametrize("output_format", ["text", "json"])
def test_provider_directory_error_returns_a_report(tmp_path, monkeypatch, capsys, command, output_format):
    config = _write_config(tmp_path)
    config.write_text(config.read_text().replace('file = "nodes.yaml"', 'file = "."'))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["subio", *command, str(config), "--format", output_format])
    assert main() == 1
    output = capsys.readouterr()
    if output_format == "json":
        assert json.loads(output.out)["status"] == "error"
    assert "IsADirectoryError" in output.out
    assert "Traceback" not in output.out + output.err


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_dist_read_failure_returns_safe_report(tmp_path, monkeypatch, capsys, output_format):
    config = _write_config(tmp_path)
    target = tmp_path / "dist" / "out.yaml"
    target.parent.mkdir()
    target.write_text("old")
    original = Path.open

    def denied(path, *args, **kwargs):
        if path.absolute() == target:
            raise PermissionError("PRIVATE_IO_CANARY")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["subio", "check", str(config), "--compare-dist", "--format", output_format])
    assert main() == 1
    output = capsys.readouterr()
    if output_format == "json":
        assert json.loads(output.out)["status"] == "error"
    assert "PermissionError" in output.out
    assert "PRIVATE_IO_CANARY" not in output.out + output.err
    assert "Traceback" not in output.out + output.err


def test_missing_git_returns_safe_cli_error(tmp_path, monkeypatch, capsys):
    config = _write_config(tmp_path)
    config.write_text(config.read_text() + '''
[[uploader]]
name = "gist"
type = "gist"
id = "synthetic"
token = "PRIVATE_TOKEN_CANARY"
[[artifact.upload]]
to = "gist"
''')

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("PRIVATE_IO_CANARY PRIVATE_TOKEN_CANARY")

    monkeypatch.setattr("subio_v2.workflow.uploader.subprocess.run", unavailable)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["subio", "convert", str(config)])
    assert main() == 1
    output = capsys.readouterr()
    assert "FileNotFoundError" in output.out
    assert "PRIVATE_IO_CANARY" not in output.out + output.err
    assert "PRIVATE_TOKEN_CANARY" not in output.out + output.err
    assert "Traceback" not in output.out + output.err

import importlib.abc
import subprocess
import sys

import pytest

from subio_v2.main import main


class _NoServerDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"starlette", "uvicorn"}:
            raise ImportError("Server dependency intentionally unavailable")


def test_base_cli_and_serve_help_do_not_import_optional_dependencies(monkeypatch, capsys):
    monkeypatch.setattr(sys, "meta_path", [_NoServerDependencies(), *sys.meta_path])
    monkeypatch.setattr(sys, "argv", ["subio", "--help"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 0
    assert "serve" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["subio", "serve", "--help"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 0
    output = capsys.readouterr().out
    assert "--port" in output and "--host" not in output


@pytest.mark.parametrize("port", ["0", "65536", "bad"])
def test_serve_cli_rejects_invalid_ports_without_loading_server(monkeypatch, capsys, port):
    monkeypatch.setattr(sys, "argv", ["subio", "serve", "--port", port])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert "Port must be an integer from 1 to 65535" in capsys.readouterr().err


def test_missing_server_extra_has_a_safe_actionable_cli_error(tmp_path):
    script = '''
import importlib.abc
import sys
class NoServer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"starlette", "uvicorn"}:
            raise ImportError("intentionally absent")
sys.meta_path.insert(0, NoServer())
from subio_v2.main import main
sys.argv = ["subio", "serve", "synthetic-config.json"]
sys.exit(main())
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert "install subio[server]" in result.stdout
    assert "Traceback" not in result.stderr

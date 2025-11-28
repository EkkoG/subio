import sys
from pathlib import Path

from subio_v2.workflow.engine import WorkflowEngine


def write(tmp_path: Path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_fetch_content_file_relative_to_config_and_provider_dir(tmp_path, monkeypatch):
    # Prepare config in a directory with provider subdir
    cfg_dir = tmp_path / "conf"
    prov_dir = cfg_dir / "provider"
    prov_dir.mkdir(parents=True)
    cfg = write(cfg_dir, "config.toml", "a = 1")

    # Create target file in config dir
    f1 = write(cfg_dir, "nodes.json5", "{a:1}")
    # And in provider subdir
    f2 = write(prov_dir, "nodes.json5", "{b:2}")

    eng = WorkflowEngine(str(cfg))

    # Case 1: file exists in config dir
    conf = {"file": "nodes.json5"}
    c1 = eng._fetch_content(conf)
    assert "a:1" in c1 or "a: 1" in c1 or "\"a\": 1" in c1

    # Case 2: when not in config dir, should find in provider subdir
    # Remove config-dir copy to force provider lookup
    f1.unlink()
    c2 = eng._fetch_content(conf)
    assert "b:2" in c2 or "b: 2" in c2 or "\"b\": 2" in c2


def test_fetch_content_url_errors_and_headers(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    eng = WorkflowEngine(str(cfg))

    # Mock requests.get to capture headers and simulate error
    captured = {"headers": None}

    class Resp:
        text = "hello"
        def raise_for_status(self):
            pass
    
    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        # Simulate failure when url contains 'fail'
        if "fail" in url:
            raise Exception("network fail")
        return Resp()

    monkeypatch.setattr("subio_v2.workflow.engine.requests.get", fake_get)

    # Success path and user_agent header
    c = eng._fetch_content({"url": "http://ok", "user_agent": "UA"})
    assert c == "hello"
    assert captured["headers"] == {"User-Agent": "UA"}

    # Failure path returns None
    c2 = eng._fetch_content({"url": "http://fail"})
    assert c2 is None

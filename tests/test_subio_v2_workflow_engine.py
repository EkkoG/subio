import sys
from pathlib import Path
import yaml

from subio_v2.workflow.engine import WorkflowEngine


def write(tmp_path: Path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_load_config_formats(tmp_path, monkeypatch):
    # TOML
    toml_p = write(tmp_path, "cfg.toml", "a = 1")
    eng = WorkflowEngine(str(toml_p))
    assert eng.config["a"] == 1
    # JSON
    json_p = write(tmp_path, "cfg.json", "{\"a\":2}")
    eng = WorkflowEngine(str(json_p))
    assert eng.config["a"] == 2
    # JSON5
    json5_p = write(tmp_path, "cfg.json5", "// c\n{a: 3}")
    eng = WorkflowEngine(str(json5_p))
    assert eng.config["a"] == 3
    # YAML
    yaml_p = write(tmp_path, "cfg.yaml", "a: 4")
    eng = WorkflowEngine(str(yaml_p))
    assert eng.config["a"] == 4


def test_write_artifact_basic_yaml_and_text(tmp_path, monkeypatch):
    # Minimal config to construct engine; no ruleset
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    eng = WorkflowEngine(str(cfg), dry_run=True)

    # Mock renderer to bypass template rendering
    class DummyRenderer:
        def render(self, *a, **kw):
            return "rendered"
    eng.renderer = DummyRenderer()

    # YAML data: should dump dict when no template
    content_yaml = {"proxies": [{"name": "n1"}, {"name": "n2"}]}
    # Ensure dist exists
    (tmp_path / "dist").mkdir(exist_ok=True)
    eng._write_artifact("out.yaml", content_yaml, template_path=None, artifact_type="clash")
    out1 = (tmp_path / "dist" / "out.yaml").read_text()
    # Should be YAML text containing proxies
    assert "proxies:" in out1 and "- name: n1" in out1

    # Text content with template: should use renderer result
    eng._write_artifact("out.txt", "rawtext", template_path="tpl", artifact_type="surge")
    out2 = (tmp_path / "dist" / "out.txt").read_text()
    assert out2 == "rendered"


def test_write_artifact_user_filename_replacement(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    eng = WorkflowEngine(str(cfg), dry_run=True)
    class DummyRenderer:
        def render(self, *a, **kw):
            return "x"
    eng.renderer = DummyRenderer()

    # Ensure dist exists
    (tmp_path / "dist").mkdir(exist_ok=True)
    eng._write_artifact("file-{user}.txt", "c", template_path=None, username="alice")
    assert (tmp_path / "dist" / "file-alice.txt").exists()

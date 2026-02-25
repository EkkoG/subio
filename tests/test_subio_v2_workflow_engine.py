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


def test_load_providers_applies_provider_level_filters(tmp_path, monkeypatch):
    """Provider 级别 filters 在 _load_providers 时应用，仅保留匹配 include/exclude 的节点"""
    # 准备 subio 格式的节点文件（包含香港、日本、美国节点）
    nodes_toml = """
[[proxies]]
name = "香港-01"
type = "ss"
server = "s1"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[proxies]]
name = "日本-01"
type = "ss"
server = "s2"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[proxies]]
name = "美国-01"
type = "ss"
server = "s3"
port = 8388
cipher = "aes-256-gcm"
password = "p"
"""
    write(tmp_path, "nodes.toml", nodes_toml.strip())

    # 配置：provider 带 filters，仅 include 香港
    config_toml = """
[[provider]]
name = "test_prov"
type = "subio"
file = "nodes.toml"

[provider.filters]
include = "香港"
"""
    cfg = write(tmp_path, "config.toml", config_toml.strip())
    monkeypatch.chdir(tmp_path)

    eng = WorkflowEngine(str(cfg), dry_run=True)
    eng._load_providers()

    assert "test_prov" in eng.providers
    nodes = eng.providers["test_prov"]
    assert len(nodes) == 1
    assert nodes[0].name == "香港-01"


def test_load_providers_provider_filters_exclude(tmp_path, monkeypatch):
    """Provider filters 支持 exclude"""
    nodes_toml = """
[[proxies]]
name = "香港-优质"
type = "ss"
server = "s1"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[proxies]]
name = "香港-剩余流量:10GB"
type = "ss"
server = "s2"
port = 8388
cipher = "aes-256-gcm"
password = "p"
"""
    write(tmp_path, "nodes.toml", nodes_toml.strip())

    config_toml = """
[[provider]]
name = "test_prov"
type = "subio"
file = "nodes.toml"

[provider.filters]
include = "香港"
exclude = "剩余流量"
"""
    cfg = write(tmp_path, "config.toml", config_toml.strip())
    monkeypatch.chdir(tmp_path)

    eng = WorkflowEngine(str(cfg), dry_run=True)
    eng._load_providers()

    nodes = eng.providers["test_prov"]
    assert len(nodes) == 1
    assert nodes[0].name == "香港-优质"


def test_load_providers_without_filters_keeps_all(tmp_path, monkeypatch):
    """没有 provider.filters 时保留所有节点"""
    nodes_toml = """
[[proxies]]
name = "node-A"
type = "ss"
server = "s"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[proxies]]
name = "node-B"
type = "ss"
server = "s"
port = 8388
cipher = "aes-256-gcm"
password = "p"
"""
    write(tmp_path, "nodes.toml", nodes_toml.strip())

    config_toml = """
[[provider]]
name = "test_prov"
type = "subio"
file = "nodes.toml"
"""
    cfg = write(tmp_path, "config.toml", config_toml.strip())
    monkeypatch.chdir(tmp_path)

    eng = WorkflowEngine(str(cfg), dry_run=True)
    eng._load_providers()

    nodes = eng.providers["test_prov"]
    assert len(nodes) == 2
    assert {n.name for n in nodes} == {"node-A", "node-B"}

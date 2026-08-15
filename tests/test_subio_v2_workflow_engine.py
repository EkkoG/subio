import stat
from pathlib import Path

import pytest

from subio_v2.conversion import IssueSeverity, WorkflowResult
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.errors import ArtifactGenerationError, ConfigError


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
    json_p = write(tmp_path, "cfg.json", '{"a":2}')
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
    eng._write_artifact(
        "out.yaml", content_yaml, template_path=None, artifact_type="clash"
    )
    eng._commit_artifacts()
    out1 = (tmp_path / "dist" / "out.yaml").read_text()
    # Should be YAML text containing proxies
    assert "proxies:" in out1 and "- name: n1" in out1
    assert stat.S_IMODE((tmp_path / "dist" / "out.yaml").stat().st_mode) == 0o600

    # Text content with template: should use renderer result
    eng._write_artifact(
        "out.txt", "rawtext", template_path="tpl", artifact_type="surge"
    )
    eng._commit_artifacts()
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
    eng._commit_artifacts()
    assert (tmp_path / "dist" / "file-alice.txt").exists()


def test_write_artifact_rejects_path_traversal(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    eng = WorkflowEngine(str(cfg), dry_run=True)

    with pytest.raises(ArtifactGenerationError, match="Invalid artifact filename"):
        eng._write_artifact("../escape.txt", "secret", template_path=None)

    assert not (tmp_path / "escape.txt").exists()


def test_config_rejects_missing_provider_reference(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[artifact]]
name = "out.yaml"
type = "clash-meta"
providers = ["missing"]
""".strip(),
    )

    with pytest.raises(ConfigError, match="missing provider"):
        WorkflowEngine(str(cfg), dry_run=True)


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


def _write_conversion_workflow(
    tmp_path: Path,
    *,
    global_options: str = "",
    artifact_options: str = "",
    nodes: str,
) -> Path:
    write(tmp_path, "nodes.yaml", nodes.strip())
    return write(
        tmp_path,
        "config.toml",
        f"""
{global_options}

[[provider]]
name = "source-provider"
type = "clash-meta"
file = "nodes.yaml"

[[artifact]]
name = "out.txt"
type = "v2rayn"
providers = ["source-provider"]
{artifact_options}
""".strip(),
    )


def test_conversion_errors_abort_before_write_and_flush(tmp_path, monkeypatch):
    cfg = _write_conversion_workflow(
        tmp_path,
        nodes="""
proxies:
  - name: unsupported
    type: hysteria2
    server: example.com
    port: 443
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)
    engine = WorkflowEngine(str(cfg), dry_run=True)
    flushed = []
    monkeypatch.setattr(engine.batch_uploader, "flush", lambda: flushed.append(True))

    with pytest.raises(ArtifactGenerationError) as exc_info:
        engine.run()

    assert exc_info.value.issues
    assert exc_info.value.issues[0].source == "source-provider"
    assert exc_info.value.issues[0].target == "v2rayn"
    assert not (tmp_path / "dist").exists()
    assert flushed == []


def test_allow_conversion_errors_still_requires_allow_empty(tmp_path, monkeypatch):
    cfg = _write_conversion_workflow(
        tmp_path,
        artifact_options="allow_conversion_errors = true",
        nodes="""
proxies:
  - name: unsupported
    type: hysteria2
    server: example.com
    port: 443
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError, match="no emit-capable nodes"):
        WorkflowEngine(str(cfg), dry_run=True).run()


def test_workflow_returns_issues_when_conversion_errors_are_allowed(
    tmp_path, monkeypatch
):
    cfg = _write_conversion_workflow(
        tmp_path,
        artifact_options="allow_conversion_errors = true",
        nodes="""
proxies:
  - name: supported
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: unsupported
    type: hysteria2
    server: example.com
    port: 443
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert isinstance(result, WorkflowResult)
    assert result.generated == ["out.txt"]
    assert result.uploaded == []
    assert len(result.errors) == 1
    assert result.errors[0].source == "source-provider"
    assert result.errors[0].node == "unsupported"
    assert (tmp_path / "dist" / "out.txt").read_text()


def test_global_allow_conversion_errors_applies_to_artifacts(tmp_path, monkeypatch):
    cfg = _write_conversion_workflow(
        tmp_path,
        global_options="allow_conversion_errors = true",
        nodes="""
proxies:
  - name: supported
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: unsupported
    type: hysteria2
    server: example.com
    port: 443
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert len(result.errors) == 1
    assert result.generated == ["out.txt"]


def test_parse_errors_abort_before_artifact_write(tmp_path, monkeypatch):
    cfg = _write_conversion_workflow(
        tmp_path,
        nodes="""
proxies:
  - name: supported
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: invalid-port
    type: ss
    server: example.com
    port: invalid
    cipher: aes-256-gcm
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    issue = exc_info.value.issues[0]
    assert issue.code == "parse.node"
    assert issue.source == "source-provider"
    assert issue.artifact == "out.txt"
    assert issue.node == "invalid-port"
    assert not (tmp_path / "dist").exists()


def test_allowed_parse_errors_are_returned_with_artifact_context(tmp_path, monkeypatch):
    cfg = _write_conversion_workflow(
        tmp_path,
        artifact_options="allow_conversion_errors = true",
        nodes="""
proxies:
  - name: supported
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: invalid-port
    type: ss
    server: example.com
    port: invalid
    cipher: aes-256-gcm
    password: p
""",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.generated == ["out.txt"]
    assert len(result.errors) == 1
    assert result.errors[0].code == "parse.node"
    assert result.errors[0].artifact == "out.txt"


def _write_surge_workflow(
    tmp_path: Path,
    *,
    providers: list[tuple[str, str]],
    artifact_options: str = "",
) -> Path:
    provider_config = []
    provider_names = []
    for name, content in providers:
        filename = f"{name}.conf"
        write(tmp_path, filename, content.strip())
        provider_names.append(name)
        provider_config.append(
            f"""
[[provider]]
name = "{name}"
type = "surge"
file = "{filename}"
""".strip()
        )
    names = ", ".join(f'"{name}"' for name in provider_names)
    return write(
        tmp_path,
        "config.toml",
        "\n\n".join(provider_config)
        + f"""


[[artifact]]
name = "out.conf"
type = "surge"
providers = [{names}]
{artifact_options}
""",
    )


def test_surge_parse_errors_abort_before_artifact_write(tmp_path, monkeypatch):
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "source",
                """
[Proxy]
good = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p
bad = vmess, example.com, invalid, username=u
""",
            )
        ],
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    issue = exc_info.value.issues[0]
    assert issue.code == "parse.line"
    assert issue.source == "source"
    assert issue.artifact == "out.conf"
    assert issue.node == "bad"
    assert not (tmp_path / "dist").exists()


def test_allowed_surge_parse_errors_are_returned(tmp_path, monkeypatch):
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "source",
                """
[Proxy]
good = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p
bad = vmess, example.com, invalid, username=u
""",
            )
        ],
        artifact_options="allow_conversion_errors = true",
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.generated == ["out.conf"]
    assert [issue.code for issue in result.errors] == ["parse.line"]
    assert "good = ss" in (tmp_path / "dist" / "out.conf").read_text()


def test_surge_workflow_uses_parse_resources_for_keystore(tmp_path, monkeypatch):
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "source",
                """
[Proxy]
ssh = ssh, example.com, 22, username=root, private-key=shared-key
[Keystore]
shared-key = type = openssh-private-key, base64 = S0VZ
""",
            )
        ],
    )
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(cfg), dry_run=True).run()

    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "private-key=shared-key" in output
    assert "[Keystore]" in output
    assert "shared-key = type = openssh-private-key, base64 = S0VZ" in output


def test_surge_workflow_rejects_conflicting_keystore_resources(tmp_path, monkeypatch):
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "first",
                """
[Proxy]
first = ssh, first.example.com, 22, username=root, private-key=shared-key
[Keystore]
shared-key = type = openssh-private-key, base64 = RklSU1Q=
""",
            ),
            (
                "second",
                """
[Proxy]
second = ssh, second.example.com, 22, username=root, private-key=shared-key
[Keystore]
shared-key = type = openssh-private-key, base64 = U0VDT05E
""",
            ),
        ],
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError, match="conflicting Surge keystore"):
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert not (tmp_path / "dist").exists()


def test_surge_resource_only_artifact_is_not_treated_as_empty(tmp_path, monkeypatch):
    write(
        tmp_path,
        "surge.tpl",
        "[Proxy]\n{{ proxies }}\n\n[Proxy Group]\n{{ proxies_names }}\n",
    )
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "source",
                """
[Proxy]
Tailnet = tailscale, section-name=office
On = direct
[Tailscale office]
auth-key = tskey-auth-example
hostname = surge-client
""",
            )
        ],
        artifact_options='template = "surge.tpl"',
    )
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(cfg), dry_run=True).run()

    output = (tmp_path / "dist" / "out.conf").read_text()
    assert "Tailnet = tailscale" in output
    assert "On = direct" in output
    assert "PROXY = select, Tailnet, On" in output


def test_surge_workflow_rejects_conflicting_named_sections(tmp_path, monkeypatch):
    cfg = _write_surge_workflow(
        tmp_path,
        providers=[
            (
                "first",
                """
[Proxy]
first = tailscale, section-name=shared
[Tailscale shared]
auth-key = first-key
""",
            ),
            (
                "second",
                """
[Proxy]
second = tailscale, section-name=shared
[Tailscale shared]
auth-key = second-key
""",
            ),
        ],
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError, match="conflicting Surge tailscale"):
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert not (tmp_path / "dist").exists()


def test_warning_only_workflow_succeeds_and_checks_each_node_once(
    tmp_path, monkeypatch
):
    cfg = _write_conversion_workflow(
        tmp_path,
        nodes="""
proxies:
  - name: tfo-node
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
    tfo: true
""",
    )
    monkeypatch.chdir(tmp_path)
    emitter = V2RayNEmitter()
    original_check = emitter.check_node
    checks = []

    def counted_check(node):
        checks.append(node.name)
        return original_check(node)

    monkeypatch.setattr(emitter, "check_node", counted_check)
    monkeypatch.setattr(
        "subio_v2.workflow.engine.EmitterFactory.get_emitter", lambda _: emitter
    )

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert checks == ["tfo-node"]
    assert result.errors == []
    assert len(result.warnings) == 1
    assert result.warnings[0].severity == IssueSeverity.INFO
    assert result.warnings[0].field == "tfo"

import os
import stat
from pathlib import Path

import pytest
import yaml

from subio_v2.core.results import ConversionIssue, IssueSeverity, WorkflowResult
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.core.errors import ArtifactGenerationError, ConfigError, UploadError
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.workflow.artifacts import (
    ArtifactDraft,
    ArtifactGenerationResult,
    ArtifactGenerationService,
)
from subio_v2.workflow.config import (
    ArtifactConfig,
    ProviderConfig,
    RunConfig,
    UploadConfig,
    UploaderConfig,
)
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.providers import ProviderLoaderService, ProviderLoadResult
from subio_v2.workflow.template import TemplateRenderResult


def write(tmp_path: Path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content)
    return p


def artifact_service(engine: WorkflowEngine) -> ArtifactGenerationService:
    return ArtifactGenerationService(
        engine.config,
        {},
        {},
        engine.renderer,
        engine._local_rulesets,
        engine.global_age_public_key,
    )


def test_load_config_formats(tmp_path, monkeypatch):
    # TOML
    toml_p = write(tmp_path, "cfg.toml", "a = 1")
    eng = WorkflowEngine(str(toml_p))
    assert eng.config.extra["a"] == 1
    assert isinstance(eng.config, RunConfig)
    assert eng.config.providers == ()
    # JSON
    json_p = write(tmp_path, "cfg.json", '{"a":2}')
    eng = WorkflowEngine(str(json_p))
    assert eng.config.extra["a"] == 2
    # JSON5
    json5_p = write(tmp_path, "cfg.json5", "// c\n{a: 3}")
    eng = WorkflowEngine(str(json5_p))
    assert eng.config.extra["a"] == 3
    # YAML
    yaml_p = write(tmp_path, "cfg.yaml", "a: 4")
    eng = WorkflowEngine(str(yaml_p))
    assert eng.config.extra["a"] == 4


def test_run_config_exposes_typed_section_records(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "p"
type = "mihomo"
file = "nodes.yaml"

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["p"]

[[uploader]]
name = "u"
type = "gist"
id = "gist-id"
""",
    )

    config = WorkflowEngine(str(cfg)).config

    assert isinstance(config.providers[0], ProviderConfig)
    assert isinstance(config.artifacts[0], ArtifactConfig)
    assert isinstance(config.uploaders[0], UploaderConfig)


def test_write_artifact_basic_yaml_and_text(tmp_path, monkeypatch):
    # Minimal config to construct engine; no ruleset
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    eng = WorkflowEngine(str(cfg), dry_run=True)

    # Mock renderer to bypass template rendering
    class DummyRenderer:
        def render_result(self, *a, **kw):
            return TemplateRenderResult("rendered")

    eng.renderer = DummyRenderer()
    service = artifact_service(eng)

    # YAML data: should dump dict when no template
    content_yaml = {"proxies": [{"name": "n1"}, {"name": "n2"}]}
    # Ensure dist exists
    (tmp_path / "dist").mkdir(exist_ok=True)
    rendered, issues = service._render_content(
        content_yaml, None, "clash", {}, None, {}, "out.yaml"
    )
    assert issues == []
    first = service._stage(
        "out.yaml", rendered, ArtifactConfig(name="out.yaml", artifact_type="clash"), None
    )
    eng.publisher.commit((first,))
    out1 = (tmp_path / "dist" / "out.yaml").read_text()
    # Should be YAML text containing proxies
    assert "proxies:" in out1 and "- name: n1" in out1
    assert stat.S_IMODE((tmp_path / "dist" / "out.yaml").stat().st_mode) == 0o600

    # Text content with template: should use renderer result
    service = artifact_service(eng)
    rendered, issues = service._render_content(
        "rawtext", "tpl", "surge", {}, None, {}, "out.txt"
    )
    assert issues == []
    second = service._stage(
        "out.txt", rendered, ArtifactConfig(name="out.txt", artifact_type="surge"), None
    )
    eng.publisher.commit((second,))
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
    service = artifact_service(eng)

    # Ensure dist exists
    (tmp_path / "dist").mkdir(exist_ok=True)
    draft = service._stage(
        "file-{user}.txt",
        "c",
        ArtifactConfig(name="file-{user}.txt", artifact_type="surge"),
        "alice",
    )
    eng.publisher.commit((draft,))
    assert (tmp_path / "dist" / "file-alice.txt").exists()


def test_commit_artifacts_is_atomic_per_file_not_for_the_whole_batch(
    tmp_path, monkeypatch
):
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    engine = WorkflowEngine(str(cfg), dry_run=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "first.txt").write_text("old-first")
    (dist / "second.txt").write_text("old-second")
    drafts = (
        ArtifactDraft("first.txt", "new-first"),
        ArtifactDraft("second.txt", "new-second"),
    )
    real_replace = os.replace
    replacements = 0

    def fail_second_replace(source, target):
        nonlocal replacements
        replacements += 1
        if replacements == 2:
            raise OSError("injected replace failure")
        real_replace(source, target)

    monkeypatch.setattr("subio_v2.workflow.engine.os.replace", fail_second_replace)

    with pytest.raises(ArtifactGenerationError, match="injected replace failure"):
        engine._commit_artifacts(drafts)

    assert (dist / "first.txt").read_text() == "new-first"
    assert (dist / "second.txt").read_text() == "old-second"
    assert not list(dist.glob(".*.tmp"))


def test_write_artifact_rejects_path_traversal(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    monkeypatch.chdir(tmp_path)
    eng = WorkflowEngine(str(cfg), dry_run=True)
    service = artifact_service(eng)

    with pytest.raises(ArtifactGenerationError, match="Invalid artifact filename"):
        service._stage(
            "../escape.txt",
            "secret",
            ArtifactConfig(name="../escape.txt", artifact_type="surge"),
            None,
        )

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


def test_clash_platform_entries_emit_one_deprecation_warning_each(
    tmp_path, monkeypatch
):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "legacy-source"
type = "clash"
file = "nodes.yml"

[[artifact]]
name = "legacy.yml"
type = "clash"
providers = ["legacy-source"]
""".strip(),
    )
    messages = []
    monkeypatch.setattr(
        "subio_v2.workflow.engine.logger.warning", messages.append
    )

    WorkflowEngine(str(cfg), dry_run=True)

    assert messages == [
        "Provider 'legacy-source' uses deprecated platform type 'clash'; "
        "use 'mihomo' for modern Mihomo configurations",
        "Artifact 'legacy.yml' uses deprecated platform type 'clash'; "
        "use 'mihomo' for modern Mihomo configurations",
    ]


def test_mihomo_is_silent_and_clash_meta_entries_emit_replacement_warnings(
    tmp_path, monkeypatch
):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "modern-source"
type = "mihomo"
file = "nodes.yml"

[[provider]]
name = "alias-source"
type = "clash-meta"
file = "nodes.yml"

[[artifact]]
name = "modern.yml"
type = "mihomo"
providers = ["modern-source"]

[[artifact]]
name = "alias.yml"
type = "clash-meta"
providers = ["alias-source"]
""".strip(),
    )
    messages = []
    monkeypatch.setattr(
        "subio_v2.workflow.engine.logger.warning", messages.append
    )

    WorkflowEngine(str(cfg), dry_run=True)

    assert messages == [
        "Provider 'alias-source' uses platform type alias 'clash-meta'; "
        "use 'mihomo' instead",
        "Artifact 'alias.yml' uses platform type alias 'clash-meta'; "
        "use 'mihomo' instead",
    ]


def test_mihomo_and_alias_workflows_preserve_same_dialect_extensions(
    tmp_path, monkeypatch
):
    write(
        tmp_path,
        "nodes.yml",
        """
proxies:
  - name: future-field
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    cipher: auto
    future-mihomo-field: false
  - name: future-transport-field
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
      future-option: false
  - name: future-protocol
    type: future-protocol
    server: example.com
    port: 443
    future-option: false
""".strip(),
    )
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[provider]]
name = "alias-source"
type = "clash-meta"
file = "nodes.yml"

[[provider]]
name = "canonical-source"
type = "mihomo"
file = "nodes.yml"

[[artifact]]
name = "alias-to-canonical.yml"
type = "mihomo"
providers = ["alias-source"]

[[artifact]]
name = "canonical-to-alias.yml"
type = "clash-meta"
providers = ["canonical-source"]
""".strip(),
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    alias_to_canonical = yaml.safe_load(
        (tmp_path / "dist" / "alias-to-canonical.yml").read_text()
    )
    canonical_to_alias = yaml.safe_load(
        (tmp_path / "dist" / "canonical-to-alias.yml").read_text()
    )
    assert alias_to_canonical == canonical_to_alias
    proxies = alias_to_canonical["proxies"]
    assert proxies[0]["future-mihomo-field"] is False
    assert proxies[1]["ws-opts"]["future-option"] is False
    assert proxies[2]["type"] == "future-protocol"
    assert proxies[2]["future-option"] is False
    assert result.issues == []


def test_duplicate_artifact_name_reports_both_entry_positions(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[artifact]]
name = "clash-for-{user}.yml"
type = "clash-meta"

[[artifact]]
name = "other.yml"
type = "clash-meta"

[[artifact]]
name = "clash-for-{user}.yml"
type = "stash"
""".strip(),
    )

    with pytest.raises(
        ConfigError,
        match=(
            r"Duplicate artifact name 'clash-for-\{user\}\.yml': "
            r"artifact entry #3 duplicates artifact entry #1"
        ),
    ):
        WorkflowEngine(str(cfg), dry_run=True)


def test_artifact_users_require_user_placeholder_in_name(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[artifact]]
name = "clash-config-normal.yml"
type = "clash-meta"
users = ["laomu", "qiyu"]
""".strip(),
    )

    with pytest.raises(
        ConfigError,
        match=(
            r"Artifact entry #1 'clash-config-normal\.yml' defines users, "
            r"so its name must contain '\{user\}'"
        ),
    ):
        WorkflowEngine(str(cfg), dry_run=True)


def test_duplicate_artifact_templates_allow_disjoint_users(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[artifact]]
name = "clash-for-{user}.yml"
type = "clash-meta"
users = ["alice"]

[[artifact]]
name = "clash-for-{user}.yml"
type = "stash"
users = ["bob"]
""".strip(),
    )

    WorkflowEngine(str(cfg), dry_run=True)


def test_duplicate_artifact_templates_report_overlapping_user(tmp_path):
    cfg = write(
        tmp_path,
        "config.toml",
        """
[[artifact]]
name = "clash-for-{user}.yml"
type = "clash-meta"
users = ["alice", "bob"]

[[artifact]]
name = "clash-for-{user}.yml"
type = "stash"
users = ["bob", "charlie"]
""".strip(),
    )

    with pytest.raises(
        ConfigError,
        match=(
            r"Duplicate artifact output name 'clash-for-bob\.yml': "
            r"artifact entry #2 \(user 'bob'\) duplicates "
            r"artifact entry #1 \(user 'bob'\)"
        ),
    ):
        WorkflowEngine(str(cfg), dry_run=True)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("options = []", "options must be an object"),
        ('[filters]\ninclude = ["hk"]', "include must be a string"),
        ('[filters]\ninclude = "["', "not a valid regex"),
        (
            '[[artifact]]\nname = "out"\ntype = "surge"\nproviders = "p"',
            "providers must be a list",
        ),
        (
            '[[artifact]]\nname = "out"\ntype = "surge"\nusers = "alice"',
            "users must be a list",
        ),
        (
            '[[artifact]]\nname = "out"\ntype = "surge"\n'
            'user = "alice"\nusers = ["bob"]',
            "cannot define both user and users",
        ),
        (
            '[[artifact]]\nname = "out"\ntype = "surge"\n'
            'upload = [{file_name = "out"}]',
            "upload target must be a non-empty string",
        ),
        (
            '[[artifact]]\nname = "out"\ntype = "surge"\n'
            'upload = [{to = "missing"}]',
            "references missing uploader",
        ),
    ],
)
def test_config_shape_errors_are_reported_as_config_errors(
    tmp_path, content, message
):
    cfg = write(tmp_path, "config.toml", content)

    with pytest.raises(ConfigError, match=message):
        WorkflowEngine(str(cfg), dry_run=True)


def test_upload_failure_aborts_the_run_queue(tmp_path, monkeypatch):
    cfg = write(tmp_path, "config.toml", "a = 1")
    engine = WorkflowEngine(str(cfg), dry_run=False)
    monkeypatch.setattr(
        "subio_v2.workflow.engine.ProviderLoaderService.load",
        lambda self, config, loader: ProviderLoadResult({}, {}),
    )

    def generate(self):
        engine.batch_uploader.add(
            "content",
            ArtifactConfig(name="out.txt", artifact_type="v2rayn"),
            UploadConfig(target="gist"),
            UploaderConfig(
                name="gist", uploader_type="gist", id="abc123", token="token"
            ),
        )
        return ArtifactGenerationResult(
            (ArtifactDraft("out.txt", "content"),), []
        )

    monkeypatch.setattr(
        "subio_v2.workflow.engine.ArtifactGenerationService.generate", generate
    )
    monkeypatch.setattr(engine, "_commit_artifacts", lambda drafts: None)

    def fail_flush():
        raise UploadError("injected upload failure")

    monkeypatch.setattr(engine.batch_uploader, "flush", fail_flush)

    with pytest.raises(UploadError, match="injected upload failure"):
        engine.run()

    assert engine.batch_uploader.pending_uploads() == []


def test_load_providers_applies_provider_level_filters(tmp_path, monkeypatch):
    """Provider 级别 filters 在 _load_providers 时应用，仅保留匹配 include/exclude 的节点"""
    # 准备 subio 格式的节点文件（包含香港、日本、美国节点）
    nodes_toml = """
version = 2

[[nodes]]
name = "香港-01"
type = "shadowsocks"
server = "s1"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[nodes]]
name = "日本-01"
type = "shadowsocks"
server = "s2"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[nodes]]
name = "美国-01"
type = "shadowsocks"
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
    result = ProviderLoaderService(str(cfg)).load(eng.config, RunRemoteLoader())

    assert "test_prov" in result.providers
    nodes = result.providers["test_prov"]
    assert len(nodes) == 1
    assert nodes[0].name == "香港-01"


def test_load_providers_provider_filters_exclude(tmp_path, monkeypatch):
    """Provider filters 支持 exclude"""
    nodes_toml = """
version = 2

[[nodes]]
name = "香港-优质"
type = "shadowsocks"
server = "s1"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[nodes]]
name = "香港-剩余流量:10GB"
type = "shadowsocks"
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
    result = ProviderLoaderService(str(cfg)).load(eng.config, RunRemoteLoader())

    nodes = result.providers["test_prov"]
    assert len(nodes) == 1
    assert nodes[0].name == "香港-优质"


def test_load_providers_without_filters_keeps_all(tmp_path, monkeypatch):
    """没有 provider.filters 时保留所有节点"""
    nodes_toml = """
version = 2

[[nodes]]
name = "node-A"
type = "shadowsocks"
server = "s"
port = 8388
cipher = "aes-256-gcm"
password = "p"

[[nodes]]
name = "node-B"
type = "shadowsocks"
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
    result = ProviderLoaderService(str(cfg)).load(eng.config, RunRemoteLoader())

    nodes = result.providers["test_prov"]
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


def _write_ruleset_issue_workflow(tmp_path: Path, *, allow_errors: bool) -> Path:
    (tmp_path / "template").mkdir()
    (tmp_path / "template" / "out.j2").write_text(
        "proxies:\n{{ proxies | indent(2, true) }}\nrules:\n"
        "{{ remote_bad('Proxy') | indent(2, true) }}\n"
    )
    write(
        tmp_path,
        "nodes.yaml",
        """
proxies:
  - name: supported
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
""".strip(),
    )
    allow_line = "allow_conversion_errors = true" if allow_errors else ""
    return write(
        tmp_path,
        "config.toml",
        f"""
[[provider]]
name = "source-provider"
type = "clash-meta"
file = "nodes.yaml"

[[artifact]]
name = "out.yaml"
type = "clash-meta"
providers = ["source-provider"]
template = "out.j2"
{allow_line}

[[ruleset]]
name = "bad"
url = "https://example.test/bad.list"
type = "surge"
""".strip(),
    )


def test_ruleset_errors_abort_before_artifact_staging(tmp_path, monkeypatch):
    cfg = _write_ruleset_issue_workflow(tmp_path, allow_errors=False)
    monkeypatch.chdir(tmp_path)
    logged_issues = []
    monkeypatch.setattr(
        BaseEmitter,
        "log_issues",
        staticmethod(lambda issues: logged_issues.extend(issues)),
    )
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b"USER-AGENT,*Safari*\n",
    )
    engine = WorkflowEngine(str(cfg), dry_run=True)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        engine.run()

    assert [issue.code for issue in exc_info.value.issues] == [
        "ruleset.unsupported-target-rule"
    ]
    assert exc_info.value.issues[0].artifact == "out.yaml"
    assert exc_info.value.issues[0].target == "mihomo"
    assert logged_issues == list(exc_info.value.issues)
    assert not (tmp_path / "dist").exists()


def test_ruleset_errors_are_logged_with_source_line_and_target(monkeypatch):
    messages = []

    class DummyLogger:
        def error(self, message):
            messages.append(("error", message))

        def warning(self, message):
            messages.append(("warning", message))

        def dim(self, message):
            messages.append(("dim", message))

    monkeypatch.setattr("subio_v2.emitter.base.logger", DummyLogger())
    BaseEmitter.log_issues(
        [
            ConversionIssue(
                severity=IssueSeverity.ERROR,
                node=None,
                protocol=None,
                source="remote_bad",
                target="stash",
                field="line 7",
                message="Rule type IN-USER cannot be rendered for stash",
                stage="render",
                code="ruleset.unsupported-target-rule",
            )
        ]
    )

    assert messages == [
        (
            "error",
            "Ruleset 'remote_bad' (line 7, target 'stash'): "
            "Rule type IN-USER cannot be rendered for stash",
        )
    ]


def test_allowed_ruleset_errors_are_returned_by_workflow(tmp_path, monkeypatch):
    cfg = _write_ruleset_issue_workflow(tmp_path, allow_errors=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b"USER-AGENT,*Safari*\n",
    )

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert result.generated == ["out.yaml"]
    assert [issue.code for issue in result.errors] == [
        "ruleset.unsupported-target-rule"
    ]
    assert result.errors[0].artifact == "out.yaml"
    assert (tmp_path / "dist" / "out.yaml").is_file()


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


def test_surge_workflow_preserves_referenced_keystore_attachment(tmp_path, monkeypatch):
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


def test_surge_workflow_rejects_conflicting_keystore_attachments(tmp_path, monkeypatch):
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

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert [issue.code for issue in exc_info.value.issues] == [
        "conversion.attachment-conflict"
    ]
    assert "shared-key" in exc_info.value.issues[0].message
    assert "FIRST" not in exc_info.value.issues[0].message
    assert "SECOND" not in exc_info.value.issues[0].message
    assert not (tmp_path / "dist").exists()


def test_surge_attachment_backed_nodes_are_not_treated_as_empty(tmp_path, monkeypatch):
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

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(cfg), dry_run=True).run()

    assert "conflicting Surge tailscale" in exc_info.value.issues[0].message
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
        "subio_v2.workflow.artifacts.get_emitter", lambda _: emitter
    )

    result = WorkflowEngine(str(cfg), dry_run=True).run()

    assert checks == ["tfo-node"]
    assert result.errors == []
    assert len(result.warnings) == 1
    assert result.warnings[0].severity == IssueSeverity.INFO
    assert result.warnings[0].field == "tfo"

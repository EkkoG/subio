import hashlib
import json
from pathlib import Path

import pytest

from subio_v2.core.errors import ArtifactGenerationError, ConfigError
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.manifest import read_manifest


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n")
    return path


def _remote_config(artifact_options: str = "", extra: str = "") -> str:
    return f"""
[[ruleset]]
name = "native"
url = "https://example.test/source.json"
type = "sing-box"
behavior = "classical"
format = "source"

[[artifact]]
name = "rules.json"
type = "sing-box-ruleset"
ruleset = "remote_native"
{artifact_options}

{extra}
"""


def test_remote_ruleset_artifact_uses_exact_store_name_and_source_v1(
    tmp_path, monkeypatch
):
    source = {
        "version": 5,
        "rules": [
            {"domain": ["one.example", "two.example"]},
            {
                "type": "logical",
                "mode": "and",
                "rules": [{"network": "tcp"}, {"port": 443}],
                "invert": True,
            },
        ],
    }
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: json.dumps(source).encode(),
    )
    config = _write(tmp_path / "config.toml", _remote_config())
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(config), dry_run=True).run()
    document = json.loads((tmp_path / "dist/rules.json").read_text())

    assert result.generated == ["rules.json"]
    assert result.errors == []
    assert document["version"] == 1
    assert len(document["rules"]) == 2
    assert document["rules"][1]["invert"] is True


def test_local_parameterized_snippet_omits_comments_and_policy_bindings(
    tmp_path, monkeypatch
):
    _write(
        tmp_path / "snippet/local_rules",
        """
default_rule, api_rule
# omitted comment
DOMAIN,one.example,PRIVATE-LITERAL
DOMAIN-SUFFIX,two.example,{{ api_rule }}
""",
    )
    config = _write(
        tmp_path / "config.toml",
        """
[[artifact]]
name = "rules.json"
type = "sing-box-ruleset"
ruleset = "local_rules"
""",
    )
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(config), dry_run=True).run()
    content = (tmp_path / "dist/rules.json").read_text()

    assert json.loads(content) == {
        "version": 1,
        "rules": [
            {"domain": "one.example"},
            {"domain_suffix": "two.example"},
        ],
    }
    assert "omitted comment" not in content
    assert "PRIVATE-LITERAL" not in content
    assert "api_rule" not in content


@pytest.mark.parametrize(
    "artifact_line",
    [
        "",
        'ruleset = ""',
        "ruleset = 1",
        'providers = ["source"]\nruleset = "local_rules"',
        'template = "rules.j2"\nruleset = "local_rules"',
        'user = "alice"\nruleset = "local_rules"',
        'selector = "chosen"\nruleset = "local_rules"',
        'options = {key = "value"}\nruleset = "local_rules"',
        'on_duplicate_name = "keep_first"\nruleset = "local_rules"',
    ],
)
def test_ruleset_artifact_rejects_missing_invalid_or_irrelevant_fields(
    tmp_path, artifact_line
):
    config = _write(
        tmp_path / "config.toml",
        f"""
[[artifact]]
name = "rules.json"
type = "sing-box-ruleset"
{artifact_line}
""",
    )

    with pytest.raises(ConfigError):
        WorkflowEngine(str(config), dry_run=True)


def test_non_ruleset_artifact_rejects_ruleset_field(tmp_path):
    config = _write(
        tmp_path / "config.toml",
        """
[[artifact]]
name = "nodes.yaml"
type = "mihomo"
ruleset = "local_rules"
""",
    )

    with pytest.raises(ConfigError, match="only valid"):
        WorkflowEngine(str(config), dry_run=True)


def test_ruleset_artifact_does_not_infer_remote_name(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b'{"version":1,"rules":[{"domain":"ok.example"}]}',
    )
    config = _write(
        tmp_path / "config.toml",
        _remote_config().replace('ruleset = "remote_native"', 'ruleset = "native"'),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError, match="references missing ruleset: native"):
        WorkflowEngine(str(config), dry_run=True).run()

    assert not (tmp_path / "dist").exists()


def test_ambiguous_local_and_remote_store_name_is_config_error(tmp_path, monkeypatch):
    _write(
        tmp_path / "snippet/remote_native",
        """
rule
DOMAIN,local.example,{{ rule }}
""",
    )
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b'{"version":1,"rules":[{"domain":"remote.example"}]}',
    )
    config = _write(tmp_path / "config.toml", _remote_config())
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError, match="Ambiguous ruleset name 'remote_native'"):
        WorkflowEngine(str(config), dry_run=True).run()


def test_ruleset_issue_gate_prevents_publication_and_upload(tmp_path, monkeypatch):
    source = {
        "version": 1,
        "rules": [
            {"query_type": "A", "domain": "must-not-survive.example"},
            {"domain": "kept.example"},
        ],
    }
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: json.dumps(source).encode(),
    )
    config = _write(
        tmp_path / "config.toml",
        _remote_config(
            'upload = [{to = "gist", file_name = "rules.json"}]',
            """
[[uploader]]
name = "gist"
type = "gist"
id = "gist-id"
""",
        ),
    )
    monkeypatch.chdir(tmp_path)
    engine = WorkflowEngine(str(config), dry_run=True)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        engine.run()

    assert [issue.code for issue in exc_info.value.issues] == [
        "ruleset.unsupported-source-rule"
    ]
    assert exc_info.value.issues[0].artifact == "rules.json"
    assert engine.batch_uploader.pending_uploads() == []
    assert not (tmp_path / "dist").exists()


def test_allowed_ruleset_errors_emit_safe_rules_and_accurate_manifest(
    tmp_path, monkeypatch
):
    source = {
        "version": 1,
        "rules": [
            {"query_type": "A", "domain": "must-not-survive.example"},
            {"domain": "kept.example"},
        ],
    }
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: json.dumps(source).encode(),
    )
    config = _write(
        tmp_path / "config.toml",
        _remote_config("allow_conversion_errors = true"),
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(config), dry_run=True, write_manifest=True).run()
    content = (tmp_path / "dist/rules.json").read_text()
    artifact = read_manifest(tmp_path / "dist")["artifacts"]["rules.json"]

    assert json.loads(content)["rules"] == [{"domain": "kept.example"}]
    assert [issue.code for issue in result.errors] == [
        "ruleset.unsupported-source-rule"
    ]
    assert artifact["type"] == "sing-box-ruleset"
    assert artifact["input_nodes"] == 2
    assert artifact["supported_nodes"] == 1
    assert artifact["bytes"] == len(content.encode())
    assert artifact["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    assert artifact["issue_codes"] == ["ruleset.unsupported-source-rule"]


@pytest.mark.parametrize("allow_empty", [False, True])
def test_ruleset_artifact_empty_behavior(tmp_path, monkeypatch, allow_empty):
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b'{"version":1,"rules":[]}',
    )
    option = "allow_empty = true" if allow_empty else ""
    config = _write(tmp_path / "config.toml", _remote_config(option))
    monkeypatch.chdir(tmp_path)

    if not allow_empty:
        with pytest.raises(ArtifactGenerationError, match="no emit-capable rules"):
            WorkflowEngine(str(config), dry_run=True).run()
        assert not (tmp_path / "dist").exists()
        return

    WorkflowEngine(str(config), dry_run=True).run()
    assert json.loads((tmp_path / "dist/rules.json").read_text()) == {
        "version": 1,
        "rules": [],
    }


def test_ruleset_artifact_flows_through_age_and_upload(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b'{"version":1,"rules":[{"domain":"ok.example"}]}',
    )
    monkeypatch.setattr(
        "subio_v2.workflow.engine.age.verify_public_key", lambda _key: None
    )
    plaintext: list[str] = []

    def encrypt_bytes(content, public_key):
        plaintext.append(content)
        assert public_key == "age1-test"
        return b"age-encrypted-rules\n"

    monkeypatch.setattr("subio_v2.workflow.artifacts.age.encrypt_bytes", encrypt_bytes)
    config = _write(
        tmp_path / "config.toml",
        _remote_config(
            'age_public_key = "age1-test"\n'
            'upload = [{to = "gist", file_name = "rules.age"}]',
            """
[[uploader]]
name = "gist"
type = "gist"
id = "gist-id"
""",
        ),
    )
    monkeypatch.chdir(tmp_path)
    engine = WorkflowEngine(str(config), dry_run=True)
    queued: list[str] = []
    real_add = engine.batch_uploader.add

    def capture_add(content, *args, **kwargs):
        queued.append(content)
        return real_add(content, *args, **kwargs)

    monkeypatch.setattr(engine.batch_uploader, "add", capture_add)
    monkeypatch.setattr(engine.batch_uploader, "flush", lambda: None)

    engine.run()

    assert json.loads(plaintext[0]) == {
        "version": 1,
        "rules": [{"domain": "ok.example"}],
    }
    assert (tmp_path / "dist/rules.json").read_text() == "age-encrypted-rules\n"
    assert queued == ["age-encrypted-rules\n"]
    assert engine.batch_uploader.pending_uploads() == ["gist-id:rules.age"]


def test_later_ruleset_artifact_failure_does_not_publish_earlier_draft(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "subio_v2.rules.runtime.load_remote_resource",
        lambda *args, **kwargs: b'{"version":1,"rules":[{"domain":"ok.example"}]}',
    )
    config = _write(
        tmp_path / "config.toml",
        _remote_config(
            extra="""
[[artifact]]
name = "missing.json"
type = "sing-box-ruleset"
ruleset = "missing"
"""
        ),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError, match="references missing ruleset: missing"):
        WorkflowEngine(str(config), dry_run=True).run()

    assert not (tmp_path / "dist").exists()

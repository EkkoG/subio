from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from subio_v2.workflow.config import (
    ArtifactConfig,
    ProviderConfig,
    RuleSetConfig,
    RunConfig,
    UploaderConfig,
)
from subio_v2.workflow.engine import WorkflowEngine


def _write_config(tmp_path: Path) -> Path:
    config = tmp_path / "config.toml"
    config.write_text(
        """
log_level = "INFO"
unknown_future_key = "preserved"

[options]
proxy_test_url = "https://connectivity-check.example.test/generate_204"

[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"
[provider.filters]
include = "^source"
[provider.rename]
add_prefix = "via-"
replace = [{ old = "source", new = "edge" }]

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["source"]
options = { work = true }
upload = [{ to = "gist", file_name = "out-{user}.yaml" }]

[[uploader]]
name = "gist"
type = "gist"
id = "fixture-gist"

[[ruleset]]
name = "rules"
url = "https://connectivity-check.example.test/rules.list"
type = "stash"
behavior = "classical"
format = "text"
""".strip()
    )
    return config


def test_config_sections_are_typed_records_without_mapping_facades(tmp_path):
    config = WorkflowEngine(str(_write_config(tmp_path)), dry_run=True).config

    assert isinstance(config, RunConfig)
    assert not isinstance(config, Mapping)
    assert not isinstance(config.providers[0], Mapping)
    assert not isinstance(config.artifacts[0], Mapping)
    assert not isinstance(config.uploaders[0], Mapping)
    assert isinstance(config.providers[0], ProviderConfig)
    assert isinstance(config.artifacts[0], ArtifactConfig)
    assert isinstance(config.uploaders[0], UploaderConfig)
    assert isinstance(config.rulesets[0], RuleSetConfig)
    assert config.extra["unknown_future_key"] == "preserved"
    assert config.providers[0].filters is not None
    assert config.providers[0].rename is not None
    assert config.providers[0].rename.replace[0].old == "source"
    assert config.artifacts[0].upload[0].target == "gist"


def test_workflow_config_consumers_do_not_read_typed_records_as_mappings():
    root = Path(__file__).parents[1] / "src" / "subio_v2" / "workflow"
    sources = {
        "engine": (root / "engine.py").read_text(),
        "providers": (root / "providers.py").read_text(),
        "artifacts": (root / "artifacts.py").read_text(),
        "uploader": (root / "uploader.py").read_text(),
    }

    assert 'self.config.get("' not in sources["engine"]
    assert "self.config[" not in sources["engine"]
    assert "provider_config.get(" not in sources["providers"]
    assert "provider_config[" not in sources["providers"]
    assert "artifact_config.get(" not in sources["artifacts"]
    assert "artifact_config[" not in sources["artifacts"]
    assert "uploader.get(" not in sources["uploader"]
    assert "artifact_config.get(" not in sources["uploader"]
    assert "class ConfigEntry" not in (
        root / "config.py"
    ).read_text()

from pathlib import Path

import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.workflow.engine import WorkflowEngine


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n")
    return path


def test_singbox_artifact_requires_full_json_template(tmp_path):
    config = _write(
        tmp_path / "config.toml",
        """
[[artifact]]
name = "nodes.json"
type = "sing-box"
""",
    )

    with pytest.raises(ConfigError, match="requires a JSON template"):
        WorkflowEngine(str(config), dry_run=True)


def test_standalone_singbox_ruleset_artifact_is_removed(tmp_path):
    config = _write(
        tmp_path / "config.toml",
        """
[[artifact]]
name = "rules.json"
type = "sing-box-ruleset"
ruleset = "local_rules"
""",
    )

    with pytest.raises(ConfigError, match="was removed"):
        WorkflowEngine(str(config), dry_run=True)


def test_singbox_artifact_rejects_legacy_ruleset_field(tmp_path):
    config = _write(
        tmp_path / "config.toml",
        """
[[artifact]]
name = "client.json"
type = "sing-box"
template = "client.json"
ruleset = "local_rules"
""",
    )

    with pytest.raises(ConfigError, match="template ruleset callable"):
        WorkflowEngine(str(config), dry_run=True)

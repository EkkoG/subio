import json
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.main import main
from subio_v2.workflow.engine import WorkflowEngine


@pytest.mark.parametrize("preset,count", [("basic", 1), ("merge", 2), ("chain", 2)])
def test_starter_projects_use_real_workflow_for_all_targets(tmp_path, preset, count):
    from subio_v2.workflow.starter import initialize_project

    root = tmp_path / preset
    config = initialize_project(root, preset=preset, targets=("mihomo", "surge", "sing-box"))
    result = WorkflowEngine(str(config), dry_run=True).prepare().artifact_result
    assert not result.issues
    documents = {draft.filename: draft.content for draft in result.drafts}
    mihomo = yaml.safe_load(documents["mihomo.yaml"])
    assert len(mihomo["proxies"]) == count
    surge = SurgeParser(source_kind="local").parse_result(documents["surge.conf"])
    assert len(surge.nodes) == count
    assert not surge.issues
    singbox = json.loads(documents["sing-box.json"])
    assert len(singbox["outbounds"]) == count
    assert singbox["route"]["final"] in {node["tag"] for node in singbox["outbounds"]}
    if preset == "chain":
        assert mihomo["proxies"][1]["dialer-proxy"] == mihomo["proxies"][0]["name"]
        assert surge.nodes[1].dialer_proxy == surge.nodes[0].name
        assert singbox["outbounds"][1]["detour"] == singbox["outbounds"][0]["tag"]
    if os.name != "nt":
        for path in root.rglob("*"):
            assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)


def test_init_cli_defaults_are_usable_by_convert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["subio", "init", "project"])
    assert main() == 0
    monkeypatch.setattr(sys, "argv", ["subio", "convert", "project/config.toml", "--dry-run"])
    assert main() == 0
    assert yaml.safe_load((tmp_path / "dist/mihomo.yaml").read_text())["proxies"]
    assert not (tmp_path / "project/template/surge.conf").exists()


@pytest.mark.parametrize("kind", ["nonempty", "file", "symlink"])
def test_init_preserves_existing_content(tmp_path, kind):
    from subio_v2.workflow.starter import initialize_project

    target = tmp_path / "project"
    if kind == "nonempty":
        target.mkdir()
        (target / "keep").write_text("original")
    elif kind == "file":
        target.write_text("original")
    else:
        destination = tmp_path / "destination"
        destination.mkdir()
        target.symlink_to(destination, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        initialize_project(target)
    if kind == "nonempty":
        assert [path.name for path in target.iterdir()] == ["keep"]
        assert (target / "keep").read_text() == "original"
    elif kind == "file":
        assert target.read_text() == "original"
    else:
        assert target.is_symlink()
        assert list(destination.iterdir()) == []


@pytest.mark.parametrize("existing", [False, True])
def test_init_cleans_only_its_files_after_write_failure(tmp_path, monkeypatch, existing):
    from subio_v2.workflow.starter import initialize_project

    target = tmp_path / "project"
    if existing:
        target.mkdir()
    original_open = Path.open

    def failing_open(path, *args, **kwargs):
        if path.name == "nodes.toml":
            raise OSError("simulated write failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(OSError):
        initialize_project(target)
    assert target.exists() == existing
    if existing:
        assert list(target.iterdir()) == []

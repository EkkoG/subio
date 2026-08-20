import json
import stat

import pytest

from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.workflow.artifacts import ArtifactSummary
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.manifest import (
    MANIFEST_NAME,
    apply_manifest,
    build_manifest,
    managed_orphans,
    read_manifest,
    write_manifest,
)
from subio_v2.workflow.providers import ProviderSummary


def summary(filename: str) -> ArtifactSummary:
    return ArtifactSummary(
        name=filename,
        artifact_type="mihomo",
        filename=filename,
        user=None,
        input_nodes=1,
        supported_nodes=1,
        content_bytes=3,
        content_sha256="a" * 64,
        issue_codes=(),
    )


def test_manifest_roundtrip_is_private_and_reports_orphans(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    manifest = build_manifest(str(config), (summary("new.yaml"),))
    write_manifest(dist, manifest)

    loaded = read_manifest(dist)

    assert loaded["version"] == 1
    assert managed_orphans(dist, loaded, {"new.yaml"}) == ()
    assert managed_orphans(dist, loaded, set()) == ("new.yaml",)
    assert stat.S_IMODE((dist / MANIFEST_NAME).stat().st_mode) == 0o600


def test_clean_dist_only_removes_previous_managed_files(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "old.yaml").write_text("old")
    (dist / "manual.txt").write_text("manual")
    write_manifest(dist, build_manifest(str(config), (summary("old.yaml"),)))

    apply_manifest(
        str(config),
        (summary("new.yaml"),),
        dist_dir=dist,
        clean=True,
    )

    assert not (dist / "old.yaml").exists()
    assert (dist / "manual.txt").read_text() == "manual"
    assert set(read_manifest(dist)["artifacts"]) == {"new.yaml"}


def test_manifest_json_is_not_artifact_content(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    write_manifest(dist, build_manifest(str(config), (summary("out.yaml"),)))

    data = json.loads((dist / MANIFEST_NAME).read_text())
    assert "content" not in data
    assert "url" not in data


def test_manifest_contains_provider_content_summary(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    write_manifest(
        dist,
        build_manifest(
            str(config),
            (summary("out.yaml"),),
            {
                "source": ProviderSummary(
                    "source", "b" * 64, parsed_nodes=2, selected_nodes=1
                )
            },
        ),
    )

    data = read_manifest(dist)

    assert data["providers"]["source"] == {
        "content_sha256": "b" * 64,
        "parsed_nodes": 2,
        "selected_nodes": 1,
    }


def test_clean_dist_missing_managed_file_is_idempotent(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    write_manifest(dist, build_manifest(str(config), (summary("old.yaml"),)))

    apply_manifest(str(config), (summary("new.yaml"),), dist_dir=dist, clean=True)

    assert set(read_manifest(dist)["artifacts"]) == {"new.yaml"}


def test_clean_dist_rejects_symlink_managed_file(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    dist.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    (dist / "old.yaml").symlink_to(target)
    write_manifest(dist, build_manifest(str(config), (summary("old.yaml"),)))

    with pytest.raises(ArtifactGenerationError, match="unsafe"):
        apply_manifest(str(config), (summary("new.yaml"),), dist_dir=dist, clean=True)


def test_clean_dist_restores_files_when_manifest_write_fails(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    dist.mkdir()
    old = dist / "old.yaml"
    old.write_text("old")
    write_manifest(dist, build_manifest(str(config), (summary("old.yaml"),)))

    def fail_write(*args, **kwargs):
        raise OSError("manifest unavailable")

    monkeypatch.setattr("subio_v2.workflow.manifest.write_manifest", fail_write)
    with pytest.raises(OSError, match="manifest unavailable"):
        apply_manifest(str(config), (summary("new.yaml"),), dist_dir=dist, clean=True)

    assert old.read_text() == "old"


def test_workflow_writes_manifest_only_when_requested(tmp_path, monkeypatch):
    (tmp_path / "nodes.yaml").write_text(
        "proxies:\n  - {name: direct, type: direct}\n"
    )
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["source"]
""".strip()
    )
    monkeypatch.chdir(tmp_path)

    WorkflowEngine(str(config), dry_run=True, write_manifest=True).run()

    assert (tmp_path / "dist" / MANIFEST_NAME).is_file()

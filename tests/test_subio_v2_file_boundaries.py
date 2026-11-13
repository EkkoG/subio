import json
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from subio_v2.core.errors import ArtifactGenerationError, UploadError
from subio_v2.workflow.artifacts import ArtifactDraft
from subio_v2.workflow.config import ArtifactConfig, UploadConfig, UploaderConfig
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.manifest import MANIFEST_NAME, apply_manifest, build_manifest, read_manifest, write_manifest
from subio_v2.workflow.publication import ArtifactPublisher
from subio_v2.workflow.uploader import GistBatchUploader
from tests.test_subio_v2_manifest import summary


def same_name(directory, first, second):
    with tempfile.TemporaryDirectory(dir=directory) as probe:
        (Path(probe) / first).touch()
        return (Path(probe) / second).exists()


@pytest.mark.parametrize("reserved", [MANIFEST_NAME, MANIFEST_NAME.upper()])
def test_reserved_names_fail_before_replacing_any_artifact(tmp_path, monkeypatch, reserved):
    monkeypatch.chdir(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "first.yaml").write_text("original")
    equivalent = same_name(tmp_path, MANIFEST_NAME, reserved)
    if equivalent:
        with pytest.raises(ArtifactGenerationError):
            ArtifactPublisher().commit([ArtifactDraft("first.yaml", "replacement"),
                                        ArtifactDraft(reserved, "forbidden")])
        assert (dist / "first.yaml").read_text() == "original"
    else:
        ArtifactPublisher().commit([ArtifactDraft(reserved, "distinct")])
        assert (dist / reserved).read_text() == "distinct"
    assert not list(dist.glob(".subio-names-*"))


@pytest.mark.parametrize("first,second", [("A.yaml", "a.yaml"), ("\u00e9.yaml", "e\u0301.yaml")])
def test_publication_follows_actual_filesystem_name_equivalence(tmp_path, monkeypatch, first, second):
    monkeypatch.chdir(tmp_path)
    if same_name(tmp_path, first, second):
        with pytest.raises(ArtifactGenerationError):
            ArtifactPublisher().commit([ArtifactDraft(first, "first"), ArtifactDraft(second, "second")])
        assert not any((tmp_path / "dist").iterdir())
    else:
        ArtifactPublisher().commit([ArtifactDraft(first, "first"), ArtifactDraft(second, "second")])
        assert (tmp_path / "dist" / first).read_text() == "first"
        assert (tmp_path / "dist" / second).read_text() == "second"


@pytest.mark.parametrize("first,second", [("A.yaml", "a.yaml"), ("\u00e9.yaml", "e\u0301.yaml")])
def test_two_round_clean_keeps_current_filesystem_alias(tmp_path, monkeypatch, first, second):
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    dist = tmp_path / "dist"
    ArtifactPublisher().commit([ArtifactDraft(first, "first")])
    write_manifest(dist, build_manifest(str(config), (summary(first),)))
    ArtifactPublisher().commit([ArtifactDraft(second, "second")])
    apply_manifest(str(config), (summary(second),), dist_dir=dist, clean=True)
    assert (dist / second).read_text() == "second"
    assert set(read_manifest(dist)["artifacts"]) == {second}
    assert not list(dist.glob(".subio-names-*"))


@pytest.mark.parametrize("name", [".git", ".GIT"])
def test_git_metadata_name_is_rejected_by_queue_on_its_filesystem(name):
    batch = GistBatchUploader(dry_run=True)
    args = ("synthetic", ArtifactConfig(name=name, artifact_type="mihomo"),
            UploadConfig(target="gist"), UploaderConfig(name="gist", uploader_type="gist", id="synthetic"))
    if same_name(tempfile.gettempdir(), ".git", name):
        with pytest.raises(UploadError):
            batch.add(*args)
        assert not batch.pending_uploads()
    else:
        batch.add(*args)
        assert batch.pending_uploads()


@pytest.mark.parametrize("existing", ["symlink", "file", "directory"])
def test_checkout_install_replaces_files_without_following_symlinks(tmp_path, monkeypatch, existing):
    victim = tmp_path / "victim"
    victim.write_text("original")
    victim.chmod(0o640)
    untouched = []

    def fake_git(args, *unused, **kwargs):
        if args[:2] == ["git", "clone"]:
            repo = Path(args[-1])
            repo.mkdir()
            (repo / "keep").write_text("keep")
            target = repo / "out.txt"
            if existing == "symlink":
                target.symlink_to(victim)
            elif existing == "directory":
                target.mkdir()
            else:
                target.write_text("old")
            untouched.append(repo / "keep")
        else:
            repo = Path(args[args.index("-C") + 1])
            assert (repo / "out.txt").is_file() and not (repo / "out.txt").is_symlink()
            assert (repo / "out.txt").read_text() == "generated"
            assert stat.S_IMODE((repo / "out.txt").stat().st_mode) == 0o600
            assert untouched[0].read_text() == "keep"
        return subprocess.CompletedProcess(args, 0, stdout="out.txt\0" if "ls-files" in args else "", stderr="")

    monkeypatch.setattr(GistBatchUploader, "_run_git", staticmethod(fake_git))
    if existing == "directory":
        with pytest.raises(UploadError):
            GistBatchUploader()._upload_batch("synthetic", "token", {"out.txt": "generated"})
    else:
        GistBatchUploader()._upload_batch("synthetic", "token", {"out.txt": "generated"})
    assert victim.read_text() == "original"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o640


def test_manifest_collision_stops_workflow_before_upload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "nodes.yaml").write_text("proxies: [{name: good, type: direct}]")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"provider": [{"name": "source", "type": "mihomo", "file": "nodes.yaml"}],
        "artifact": [{"name": MANIFEST_NAME, "type": "mihomo", "providers": ["source"],
                      "upload": [{"to": "gist"}]}],
        "uploader": [{"name": "gist", "type": "gist", "id": "synthetic", "token": "synthetic"}]}))
    monkeypatch.setattr(GistBatchUploader, "flush", lambda *_: pytest.fail("uploaded collision"))
    with pytest.raises(ArtifactGenerationError):
        WorkflowEngine(str(config), write_manifest=True).run()
    assert not (tmp_path / "dist" / MANIFEST_NAME).exists()

import os
import stat
from contextlib import closing

import pytest

from subio_v2.main import _atomic_write_bytes
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.workflow.artifacts import ArtifactDraft
from subio_v2.workflow.manifest import apply_manifest, build_manifest, write_manifest, MANIFEST_NAME
from subio_v2.workflow.publication import ArtifactPublisher
from tests.test_subio_v2_manifest import summary
from tests.test_subio_v2_remote_cache import Response, Session


def test_missing_fchmod_preserves_all_write_owners(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delattr(os, "fchmod")
    _atomic_write_bytes("plaintext", b"synthetic")
    ArtifactPublisher().commit([ArtifactDraft("out.yaml", "synthetic")])
    write_manifest(tmp_path / "dist", {"version": 1, "artifacts": {}})
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session",
                        lambda: Session([Response()]))
    with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path / "cache")) as loader:
        assert loader.fetch("https://example.test/data") == b"payload"
    assert (tmp_path / "plaintext").read_bytes() == b"synthetic"
    assert (tmp_path / "dist" / "out.yaml").read_text() == "synthetic"
    assert list((tmp_path / "cache").glob("*.json"))
    for path in [tmp_path / "plaintext", tmp_path / "dist" / "out.yaml",
                 tmp_path / "dist" / MANIFEST_NAME]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_optional_cache_permission_failure_keeps_download(tmp_path, monkeypatch):
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session",
                        lambda: Session([Response()]))
    def denied(*args, **kwargs):
        raise PermissionError("synthetic")
    monkeypatch.setattr(os, "fchmod", denied)
    with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)) as loader:
        assert loader.fetch("https://example.test/data") == b"payload"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("owner", ["atomic", "publisher", "manifest", "cache"])
def test_interrupt_removes_unpublished_temporary_plaintext(tmp_path, monkeypatch, owner):
    monkeypatch.chdir(tmp_path)
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        if owner == "atomic":
            _atomic_write_bytes("output", b"PLAINTEXT_CANARY")
        elif owner == "publisher":
            ArtifactPublisher().commit([ArtifactDraft("output", "PLAINTEXT_CANARY")])
        elif owner == "manifest":
            write_manifest(tmp_path / "dist", {"canary": "PLAINTEXT_CANARY"})
        else:
            monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session",
                                lambda: Session([Response(content=b"PLAINTEXT_CANARY")]))
            with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path / "cache")) as loader:
                loader.fetch("https://example.test/data")
    assert not [path for path in tmp_path.rglob("*") if path.is_file()]


def test_legal_long_names_publish_and_clean_without_long_temp_prefix(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    filename = "x" * 245 + ".yaml"
    _atomic_write_bytes(filename, b"atomic")
    ArtifactPublisher().commit([ArtifactDraft(filename, "artifact")])
    assert (tmp_path / filename).read_bytes() == b"atomic"
    assert (tmp_path / "dist" / filename).read_text() == "artifact"
    config = tmp_path / "config.toml"
    config.write_text("options = {}")
    write_manifest(tmp_path / "dist", build_manifest(str(config), (summary(filename),)))
    apply_manifest(str(config), (), dist_dir=tmp_path / "dist", clean=True)
    assert not (tmp_path / "dist" / filename).exists()
    assert {path.name for path in (tmp_path / "dist").iterdir()} == {MANIFEST_NAME}

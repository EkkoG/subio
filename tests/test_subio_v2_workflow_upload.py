import subprocess
from pathlib import Path

import pytest

from subio_v2.errors import UploadError
from subio_v2.workflow.uploader import GistBatchUploader, upload


def test_upload_queues_to_gist_and_flush(monkeypatch):
    batch = GistBatchUploader(dry_run=True, clean_gist=True)
    artifact_conf = {
        "name": "out.txt",
        "upload": [{"to": "gist1", "file_name": "file-{user}.txt"}],
    }
    uploader_configs = [
        {
            "name": "gist1",
            "type": "gist",
            "id": "abc123",
            "token": "ENV_FAKE",
        }
    ]

    upload(
        "content",
        artifact_conf,
        uploader_configs,
        batch,
        username="alice",
    )

    assert batch.pending_uploads() == ["abc123:file-alice.txt"]
    monkeypatch.setattr(
        "subio_v2.workflow.uploader.subprocess.run",
        lambda *args, **kwargs: pytest.fail("dry-run must not execute git"),
    )
    batch.flush()
    assert batch.pending_uploads() == []


def test_uploader_begin_and_abort_discard_pending_files():
    batch = GistBatchUploader(dry_run=True)
    uploader = {"name": "gist1", "id": "abc123", "token": ""}
    batch.add("old", {"name": "old.txt"}, {}, uploader)

    batch.begin()
    assert batch.pending_uploads() == []

    batch.add("new", {"name": "new.txt"}, {}, uploader)
    batch.abort()
    assert batch.pending_uploads() == []


def test_real_upload_requires_environment_token(monkeypatch):
    monkeypatch.delenv("MISSING_GIST_TOKEN", raising=False)
    batch = GistBatchUploader()
    artifact_conf = {"name": "out.txt", "upload": [{"to": "gist1"}]}
    uploader_configs = [
        {
            "name": "gist1",
            "type": "gist",
            "id": "abc123",
            "token": "ENV_MISSING_GIST_TOKEN",
        }
    ]

    with pytest.raises(UploadError, match="MISSING_GIST_TOKEN"):
        upload("content", artifact_conf, uploader_configs, batch)


def test_upload_rejects_path_traversal_filename():
    batch = GistBatchUploader(dry_run=True)
    artifact_conf = {
        "name": "out.txt",
        "upload": [{"to": "gist1", "file_name": "../secret.txt"}],
    }
    uploader_configs = [{"name": "gist1", "type": "gist", "id": "abc123", "token": ""}]

    with pytest.raises(UploadError, match="Invalid upload filename"):
        upload("content", artifact_conf, uploader_configs, batch)


def test_gist_token_is_not_put_in_git_argv(monkeypatch):
    token = "super-secret-token"
    monkeypatch.setenv("TEST_GIST_TOKEN", token)
    batch = GistBatchUploader()
    upload(
        "content",
        {"name": "out.txt", "upload": [{"to": "gist1"}]},
        [
            {
                "name": "gist1",
                "type": "gist",
                "id": "abc123",
                "token": "ENV_TEST_GIST_TOKEN",
            }
        ],
        batch,
    )

    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs.get("env", {})))
        if args[:2] == ["git", "clone"]:
            Path(args[-1]).mkdir()
        return_code = 1 if args[-2:] == ["--cached", "--quiet"] else 0
        stdout = " out.txt | 1 +" if args[-2:] == ["--cached", "--stat"] else ""
        return subprocess.CompletedProcess(args, return_code, stdout=stdout, stderr="")

    monkeypatch.setattr("subio_v2.workflow.uploader.subprocess.run", fake_run)
    batch.flush()

    assert calls
    assert all(token not in repr(args) for args, _ in calls)
    assert calls[0][0][2] == "https://gist.github.com/abc123.git"
    assert all(env["SUBIO_GIST_TOKEN"] == token for _, env in calls)

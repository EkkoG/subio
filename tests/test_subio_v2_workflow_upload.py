import os
from subio_v2.workflow.uploader import upload, flush_uploads, get_gist_batch_uploader


class DummyBatch:
    def __init__(self):
        self.add_calls = []
        self.flushed = False
    def add(self, content, artifact_config, upload_item, uploader, username):
        self.add_calls.append((content, artifact_config, upload_item, uploader, username))
    def flush(self):
        self.flushed = True


def test_upload_queues_to_gist_and_flush(monkeypatch):
    # Replace global getter to return dummy instance
    dummy = DummyBatch()
    monkeypatch.setattr("subio_v2.workflow.uploader.get_gist_batch_uploader", lambda **kwargs: dummy)

    artifact_conf = {"name": "out.txt", "upload": [{"to": "gist1", "file_name": "file.txt"}]}
    uploader_configs = [{"name": "gist1", "type": "gist", "id": "abc123", "token": "ENV_FAKE"}]
    # ENV token absent should log error and skip; simulate presence
    monkeypatch.setenv("FAKE", "tok")
    uploader_configs[0]["token"] = "ENV_FAKE"

    upload("content", artifact_conf, uploader_configs, username="alice", dry_run=True, clean_gist=True)
    # Ensure add called once with proper args
    assert len(dummy.add_calls) == 1
    content, art, upload_item, uploader, user = dummy.add_calls[0]
    assert content == "content" and user == "alice"
    assert upload_item["file_name"] == "file.txt"

    # flush_uploads should call flush on dummy
    monkeypatch.setattr("subio_v2.workflow.uploader._gist_batch_uploader", dummy, raising=False)
    flush_uploads(dry_run=True, clean_gist=True)
    assert dummy.flushed is True

import stat

import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.infrastructure.remote import RemoteLoadError, RunRemoteLoader
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.providers import ProviderLoadResult
from subio_v2.workflow.report import build_report


class Response:
    def __init__(self, status_code=200, content=b"payload", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        yield self.content


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.closed = False

    def mount(self, *args, **kwargs):
        return None

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers, timeout))
        return next(self.responses)

    def close(self):
        self.closed = True


def test_remote_loader_reuses_session_and_parses_metadata(monkeypatch):
    session = Session(
        [
            Response(
                headers={
                    "ETag": "etag-1",
                    "Last-Modified": "yesterday",
                    "Subscription-UserInfo": "upload=1; download=2; total=3; expire=4",
                }
            )
        ]
    )
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)

    loader = RunRemoteLoader(timeout=7)
    result = loader.fetch_result("https://example.test/sub")

    assert result.content == b"payload"
    assert result.metadata.state == "network"
    assert result.metadata.etag == "etag-1"
    assert result.metadata.subscription_user_info == {
        "upload": 1,
        "download": 2,
        "total": 3,
        "expire": 4,
    }
    assert len(session.calls) == 1
    assert session.calls[0][2] == 7
    loader.close()
    assert session.closed


def test_remote_loader_enforces_response_limit(monkeypatch):
    session = Session([Response(content=b"12345")])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)

    with pytest.raises(RemoteLoadError, match="size limit"):
        RunRemoteLoader(max_bytes=4).fetch("https://example.test/large")


def test_remote_loader_disk_cache_uses_conditional_request(tmp_path, monkeypatch):
    sessions = [
        Session([Response(headers={"ETag": "etag-1"})]),
        Session([Response(status_code=304)]),
    ]
    monkeypatch.setattr(
        "subio_v2.infrastructure.remote.requests.Session",
        lambda: sessions.pop(0),
    )

    first = RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)
    assert first.fetch("https://example.test/data") == b"payload"
    second = RunRemoteLoader(cache_enabled=True, cache_ttl=0, cache_dir=tmp_path)
    result = second.fetch_result("https://example.test/data")

    assert result.content == b"payload"
    assert result.metadata.state == "not-modified"
    assert second.last_result is result
    assert second._session.calls[0][1]["If-None-Match"] == "etag-1"
    files = list(tmp_path.iterdir())
    assert files
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


def test_remote_loader_can_explicitly_use_stale_cache_on_error(tmp_path, monkeypatch):
    class ErrorSession(Session):
        def get(self, url, headers=None, timeout=None):
            raise RuntimeError("network")

    sessions = [Session([Response()]), ErrorSession([])]
    warnings = []
    monkeypatch.setattr(
        "subio_v2.infrastructure.remote.logger.warning", warnings.append
    )
    monkeypatch.setattr(
        "subio_v2.infrastructure.remote.requests.Session",
        lambda: sessions.pop(0),
    )

    RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path).fetch(
        "https://example.test/data"
    )
    stale = RunRemoteLoader(
        cache_enabled=True,
        cache_ttl=0,
        stale_if_error=True,
        cache_dir=tmp_path,
    ).fetch_result("https://example.test/data")

    assert stale.content == b"payload"
    assert stale.metadata.state == "stale"
    assert warnings == [
        "Using stale cached remote resource after the request failed"
    ]


def test_remote_config_validates_limits_and_cache_flags():
    with pytest.raises(ConfigError, match="max_bytes"):
        ConfigValidator.validate({"remote": {"max_bytes": 0}})
    with pytest.raises(ConfigError, match="stale_if_error"):
        ConfigValidator.validate(
            {"remote": {"cache": {"stale_if_error": "yes"}}}
        )


def test_provider_metadata_is_reported_without_source_content():
    from subio_v2.infrastructure.remote import RemoteMetadata

    report = build_report(
        ProviderLoadResult(
            {"remote": []},
            {},
            {
                "remote": RemoteMetadata(
                    state="network",
                    subscription_user_info={"total": 100, "expire": 200},
                )
            },
        )
    )

    assert report["providers"][0]["remote"]["subscription_user_info"] == {
        "total": 100,
        "expire": 200,
    }
    assert "content" not in report["providers"][0]["remote"]

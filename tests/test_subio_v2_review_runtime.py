import asyncio
import json
import threading
import time
from contextlib import closing
from types import MappingProxyType

import pytest
import yaml

from subio_v2 import server
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.workflow.template import TemplateRenderer
from tests.test_subio_v2_remote_cache import Response, Session
from tests.test_subio_v2_server import TOKEN, _service
from tests.test_subio_v2_server_snapshots import _static


@pytest.mark.parametrize("expression", [
    '{"settings": params} | tojson', '{"settings": [params]} | to_yaml',
    '[params]', '[{"settings": params}] | to_yaml',
])
def test_nested_readonly_params_are_plain_serializable_data(tmp_path, expression):
    params = MappingProxyType({"credential": "synthetic", "nested": MappingProxyType({"n": 1})})
    (tmp_path / "client.j2").write_text("{{ " + expression + " }}")
    output = TemplateRenderer(str(tmp_path)).render("client.j2", {"params": params})
    assert "mappingproxy" not in output and "python/" not in output
    value = json.loads(output) if "tojson" in expression else yaml.safe_load(output)
    assert "synthetic" in str(value)
    assert params["nested"]["n"] == 1
    with pytest.raises(TypeError):
        params["nested"]["n"] = 2


@pytest.mark.parametrize("headers,expected", [
    ({"ETag": "new", "Last-Modified": "today", "Subscription-Userinfo": "download=50"},
     ("new", "today", {"download": 50})),
    ({}, ("old", "yesterday", {"download": 1})),
    ({"ETag": "", "Subscription-Userinfo": "invalid"}, ("", "yesterday", None)),
])
def test_not_modified_metadata_is_merged_and_persisted(tmp_path, monkeypatch, headers, expected):
    sessions = iter([
        Session([Response(content=b"original", headers={"ETag": "old", "Last-Modified": "yesterday",
                                                   "Subscription-Userinfo": "download=1"})]),
        Session([Response(status_code=304, content=b"", headers=headers)]),
        Session([]),
    ])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: next(sessions))
    url = "https://example.test/data"
    with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)) as loader:
        loader.fetch_result(url)
    with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path, cache_ttl=0)) as loader:
        result = loader.fetch_result(url)
        assert result.content == b"original"
        assert result.metadata.content_length == len(b"original")
        assert (result.metadata.etag, result.metadata.last_modified,
                result.metadata.subscription_user_info) == expected
    with closing(RunRemoteLoader(cache_enabled=True, cache_dir=tmp_path)) as loader:
        persisted = loader.fetch_result(url)
        assert persisted.content == result.content
        assert (persisted.metadata.etag, persisted.metadata.last_modified,
                persisted.metadata.subscription_user_info) == expected


@pytest.mark.parametrize("failure", ["cancelled", "failed", "shutdown-cancelled"])
@pytest.mark.parametrize("worker_kind", ["render", "refresh"])
def test_failed_refresh_task_still_drains_workers_and_clears_state(tmp_path, monkeypatch, failure, worker_kind):
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    path, _ = _static(tmp_path)
    app = server.create_app(str(path))
    service = _service(app)
    release = threading.Event()
    started = threading.Event()
    finished = threading.Event()

    def work():
        started.set()
        assert release.wait(timeout=5)
        finished.set()

    async def exercise():
        lifecycle = service.lifespan(app)
        await lifecycle.__aenter__()
        render, refresh = service._executor, service._refresh_executor
        (render if worker_kind == "render" else refresh).submit(work)
        while not started.is_set():
            await asyncio.sleep(0)
        service._refresh_task.cancel()
        try:
            await service._refresh_task
        except asyncio.CancelledError:
            pass
        if failure == "failed":
            async def failed():
                raise ValueError("synthetic failure")
            service._refresh_task = asyncio.create_task(failed())
            await asyncio.sleep(0)
        exiting = asyncio.create_task(lifecycle.__aexit__(None, None, None))
        try:
            # Let cleanup reach the worker wait before releasing the barrier.
            for _ in range(20):
                await asyncio.sleep(0)
            assert not exiting.done()
            if failure == "shutdown-cancelled":
                exiting.cancel()
                for _ in range(20):
                    await asyncio.sleep(0)
                assert not exiting.done()
            release.set()
            expected = ValueError if failure == "failed" else asyncio.CancelledError
            with pytest.raises(expected):
                await asyncio.wait_for(exiting, timeout=5)
            assert finished.is_set()
            assert render._shutdown and refresh._shutdown
            assert service._executor is None and service._refresh_executor is None
            assert not service._snapshots
        finally:
            release.set()
            render.shutdown(wait=True)
            refresh.shutdown(wait=True)
            if exiting.done():
                try:
                    exiting.result()
                except BaseException:
                    pass

    asyncio.run(exercise())


def test_expired_initial_snapshot_cannot_start_service(tmp_path, monkeypatch):
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    path, _ = _static(tmp_path)
    app = server.create_app(str(path), refresh_interval=1, max_snapshot_age=1)
    service = _service(app)
    prepare = service._prepare_attempt

    def expired():
        _, prepared = prepare()
        return time.monotonic() - 2, prepared

    monkeypatch.setattr(service, "_prepare_attempt", expired)

    async def exercise():
        async with service.lifespan(app):
            pytest.fail("Expired initial snapshots started the service")

    with pytest.raises(server.ServerPreparationError):
        asyncio.run(exercise())
    assert service._executor is None and service._refresh_executor is None
    assert not service._snapshots

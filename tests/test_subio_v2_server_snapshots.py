"""HTTP lifecycle contracts use synthetic resources, event barriers and a fake clock."""

import asyncio
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode
from urllib.request import urlopen

import pytest
import yaml

pytest.importorskip("starlette")
pytest.importorskip("uvicorn")
pytest.importorskip("httpx")
from starlette.testclient import TestClient

from subio_v2 import server
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.adapters.subio.parser import SubioParser
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.rendering import PreparedArtifact
from tests.test_subio_v2_server import TOKEN, _fixture, _headers, _query, _raw_request, _save, _service


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)


@pytest.mark.parametrize("interval,age", [
    (0, 900), (-1, 900), (1.0, 900), (True, 900), (300, 0),
    (300, "900"), (300, False), (301, 300),
])
def test_app_validates_freshness_before_config_io(tmp_path, monkeypatch, interval, age):
    monkeypatch.setattr(server.ConfigLoader, "load", lambda *_: pytest.fail("Loaded invalid service options"))
    with pytest.raises(server.ServerConfigurationError):
        server.create_app(str(tmp_path / "missing"), refresh_interval=interval, max_snapshot_age=age)


def test_serve_reports_all_unready_without_framework_logs_or_secrets(tmp_path, capsys):
    path, _ = _static(tmp_path)
    (tmp_path / "nodes.yaml").unlink()
    assert server.serve(str(path)) == 1
    captured = capsys.readouterr()
    output = " ".join((captured.out + captured.err).split())
    assert "resource preparation failed (provider: unavailable)" in output
    assert "check configured sources and templates" in output
    assert TOKEN not in output and str(tmp_path) not in output and "Traceback" not in output


def _clock(monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=lambda: clock.now))
    return clock


def _static(tmp_path, family="mihomo"):
    path, data = _fixture(tmp_path, family)
    data["provider"][0]["parameterized"] = False
    _save(path, data)
    _source(tmp_path, family)
    return path, data


def _source(tmp_path, family="mihomo", *, name="first", invalid=False, fatal=False):
    node = {"name": name, "type": "socks5", "server": "example.test", "port": 0 if invalid else 1080}
    document = {"version": 2, "nodes": [node]} if family == "subio" else {"proxies": [node]}
    if fatal:
        document = {"version": 1, "nodes": []}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))


@pytest.mark.parametrize("family,invalid_kind", [("mihomo", "node"), ("subio", "node"), ("subio", "fatal")])
@pytest.mark.parametrize("warm_invalid", [False, True])
def test_acquisition_age_and_complete_error_transition_matrix(
    tmp_path, monkeypatch, family, invalid_kind, warm_invalid
):
    path, _ = _static(tmp_path, family)
    clock = _clock(monkeypatch)
    if warm_invalid:
        _source(tmp_path, family, invalid=True, fatal=invalid_kind == "fatal")
    app = server.create_app(str(path), refresh_interval=10, max_snapshot_age=30)
    service = _service(app)
    with TestClient(app) as client:
        def status():
            response = client.get("/subscription/out.yaml?" + _query())
            _headers(response)
            return response.status_code

        assert status() == (422 if warm_invalid else 200)
        initial = service._snapshots["out.yaml"]
        assert initial.acquired_at == 0
        clock.now = 10
        _source(tmp_path, family, invalid=True, fatal=invalid_kind == "fatal")
        client.portal.call(service._refresh)
        invalid = service._snapshots["out.yaml"]
        assert invalid is not initial and invalid.acquired_at == 10
        assert status() == 422
        clock.now = 25
        client.portal.call(service._refresh)
        repeated = service._snapshots["out.yaml"]
        assert repeated is not invalid and repeated.acquired_at == 25
        assert status() == 422
        (tmp_path / "nodes.yaml").unlink()
        clock.now = 40
        client.portal.call(service._refresh)
        assert service._snapshots["out.yaml"] is repeated
        assert status() == 422
        clock.now = 54.999
        assert status() == 422
        clock.now = 55
        assert status() == 503
        clock.now = 60
        _source(tmp_path, family, name="recovered")
        client.portal.call(service._refresh)
        assert service._snapshots["out.yaml"].acquired_at == 60
        assert status() == 200
        assert yaml.safe_load(client.get("/subscription/out.yaml?" + _query()).text)["proxies"][0]["name"] == "recovered"


@pytest.mark.parametrize("failure", ["empty", "utf8", "serialization", "decrypt", "acquisition"])
def test_failed_preparation_never_reages_a_previous_snapshot(tmp_path, monkeypatch, failure):
    path, data = _static(tmp_path)
    if failure == "decrypt":
        from subio_v2.infrastructure import age
        secret, public = age.generate_x25519_keypair()
        data["age_secret_key"] = secret
        _save(path, data)
        (tmp_path / "nodes.yaml").write_bytes(age.encrypt_bytes((tmp_path / "nodes.yaml").read_bytes(), public))
    clock = _clock(monkeypatch)
    app = server.create_app(str(path), refresh_interval=10, max_snapshot_age=30)
    service = _service(app)
    with TestClient(app) as client:
        snapshot = service._snapshots["out.yaml"]
        clock.now = 15
        source = tmp_path / "nodes.yaml"
        if failure == "acquisition":
            source.unlink()
        else:
            source.write_bytes({"empty": b"", "utf8": b"\xff", "serialization": b"proxies: [", "decrypt": b"age-encryption.org/v1\nbroken"}[failure])
        client.portal.call(service._refresh)
        assert service._snapshots["out.yaml"] is snapshot
        assert service._failures["out.yaml"].phase == "provider"
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
        clock.now = 30
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 503


def test_partial_readiness_batch_identity_and_independent_refresh(tmp_path, monkeypatch):
    path, data = _static(tmp_path)
    data["artifact"][0].update(name="user-{user}.yaml", users=["alice", "bob"])
    data["provider"].append({"name": "missing", "type": "mihomo", "file": "missing.yaml"})
    data["artifact"].append({"name": "other.yaml", "type": "mihomo", "providers": ["missing"]})
    _save(path, data)
    clock = _clock(monkeypatch)
    app = server.create_app(str(path), refresh_interval=10, max_snapshot_age=30)
    service = _service(app)
    with TestClient(app) as client:
        alice = service._snapshots["user-alice.yaml"]
        bob = service._snapshots["user-bob.yaml"]
        assert alice.artifact is bob.artifact
        assert client.get("/subscription/user-alice.yaml?" + _query()).status_code == 200
        assert client.get("/subscription/other.yaml?" + _query()).status_code == 503
        clock.now = 10
        (tmp_path / "missing.yaml").write_text((tmp_path / "nodes.yaml").read_text())
        (tmp_path / "nodes.yaml").unlink()
        client.portal.call(service._refresh)
        assert service._snapshots["user-alice.yaml"] is alice
        assert service._snapshots["other.yaml"].acquired_at == 10
        clock.now = 30
        assert client.get("/subscription/user-bob.yaml?" + _query()).status_code == 503
        assert client.get("/subscription/other.yaml?" + _query()).status_code == 200


def test_broken_template_blocks_only_its_route_and_recovers_on_refresh(tmp_path):
    path, data = _static(tmp_path)
    data["artifact"].append({
        "name": "other.yaml", "type": "mihomo", "providers": ["source"], "template": "broken.j2"
    })
    _save(path, data)
    (tmp_path / "broken.j2").write_text("{% broken syntax")
    app = server.create_app(str(path))
    with TestClient(app) as client:
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
        assert client.get("/subscription/other.yaml?" + _query()).status_code == 503
        (tmp_path / "broken.j2").write_text("{{ nodes.render() }}")
        client.portal.call(_service(app)._refresh)
        assert client.get("/subscription/other.yaml?" + _query()).status_code == 200


@pytest.mark.parametrize("outcome", ["success", "partial", "all_unready", "shared_ruleset"])
def test_every_warmup_round_closes_real_loader_sessions(tmp_path, monkeypatch, outcome):
    path, data = _static(tmp_path)
    data["provider"][0].pop("file")
    data["provider"][0]["url"] = "https://synthetic.test/nodes"
    data["remote"] = {"cache": {"enabled": True, "stale_if_error": True}}
    if outcome in {"partial", "all_unready"}:
        data["provider"].append({"name": "missing", "type": "mihomo", "url": "https://synthetic.test/missing"})
        if outcome == "partial":
            data["artifact"].append({"name": "missing.yaml", "type": "mihomo", "providers": ["missing"]})
        else:
            data["artifact"][0]["providers"].append("missing")
    if outcome == "shared_ruleset":
        data["ruleset"] = [{"name": "shared", "url": "https://synthetic.test/missing"}]
    _save(path, data)
    loaders, sessions, closed = [], [], []
    initialize = RunRemoteLoader.__init__

    def init(loader, **kwargs):
        assert kwargs["cache_enabled"] is False and kwargs["stale_if_error"] is False
        initialize(loader, **kwargs)
        loaders.append(loader)
        session = loader._session
        sessions.append(session)
        close = session.close

        def tracked_close():
            closed.append(session)
            close()

        monkeypatch.setattr(session, "close", tracked_close)

    def get(session, url, **kwargs):
        if url.endswith("missing"):
            raise RuntimeError("synthetic_secret_not_for_diagnostics")
        return SimpleNamespace(status_code=200, headers={}, raise_for_status=lambda: None,
                               content=(tmp_path / "nodes.yaml").read_bytes())

    monkeypatch.setattr(RunRemoteLoader, "__init__", init)
    monkeypatch.setattr("requests.Session.get", get)
    app = server.create_app(str(path))
    if outcome in {"all_unready", "shared_ruleset"}:
        with pytest.raises(server.ServerPreparationError):
            with TestClient(app):
                pytest.fail("Started without a candidate")
    else:
        with TestClient(app) as client:
            assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
            assert all(loader._session is None for loader in loaders)
            client.portal.call(_service(app)._refresh)
            assert len(loaders) == 2
    assert loaders and all(loader._session is None for loader in loaders)
    assert closed == sessions


def test_inflight_request_captures_complete_nodes_rules_and_template_version(tmp_path, monkeypatch):
    path, _ = _static(tmp_path)
    snippets = tmp_path / "snippet"
    snippets.mkdir()
    (snippets / "shared").write_text("policy\nDOMAIN,first.test")
    template = tmp_path / "client.j2"
    template.write_text('first|{{ nodes.render() }}|{{ shared("DIRECT") }}')
    app = server.create_app(str(path))
    service = _service(app)
    entered, release = threading.Event(), threading.Event()
    render = PreparedArtifact.render

    def blocked(candidate, *args):
        if threading.current_thread().name.startswith("subio-render") and not release.is_set():
            entered.set()
            assert release.wait(5)
        return render(candidate, *args)

    monkeypatch.setattr(PreparedArtifact, "render", blocked)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        old = pool.submit(client.get, "/subscription/out.yaml?" + _query())
        try:
            assert entered.wait(5)
            original = service._snapshots["out.yaml"]
            _source(tmp_path, name="second")
            (snippets / "shared").write_text("policy\nDOMAIN,second.test")
            template.write_text('second|{{ nodes.render() }}|{{ shared("DIRECT") }}')
            # Local edits are invisible until this explicit refresh completes.
            assert service._snapshots["out.yaml"] is original
            client.portal.call(service._refresh)
            assert service._snapshots["out.yaml"] is not original
        finally:
            release.set()
        first = old.result(5)
        second = client.get("/subscription/out.yaml?" + _query())
        assert first.status_code == second.status_code == 200
        assert first.text.startswith("first|") and "first.test" in first.text and "name: first" in first.text
        assert "second" not in first.text
        assert second.text.startswith("second|") and "second.test" in second.text and "name: second" in second.text


def test_sequential_timer_slow_refresh_expiry_and_active_shutdown(tmp_path, monkeypatch):
    path, _ = _static(tmp_path)
    clock = _clock(monkeypatch)
    app = server.create_app(str(path), refresh_interval=10, max_snapshot_age=30)
    service = _service(app)
    prepare = server.prepare_resources
    started, release = threading.Event(), threading.Event()
    attempts = []
    active = 0
    maximum = 0

    def slow(*args):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        attempts.append((clock.now, threading.current_thread().name))
        try:
            if len(attempts) > 1:
                started.set()
                assert release.wait(10)
            return prepare(*args)
        finally:
            active -= 1

    monkeypatch.setattr(server, "prepare_resources", slow)
    ticks = asyncio.Queue()
    waits = asyncio.Queue()
    real_asyncio = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio)})

    async def wait_for_refresh(awaitable, timeout):
        assert timeout == 10
        awaitable.close()
        waits.put_nowait(clock.now)
        await ticks.get()
        if not service._stop.is_set():
            raise TimeoutError
        return True

    real_asyncio.wait_for = wait_for_refresh
    monkeypatch.setattr(server, "asyncio", real_asyncio)

    async def exercise():
        lifecycle = app.router.lifespan_context(app)
        await lifecycle.__aenter__()
        assert await waits.get() == 0
        clock.now = 10
        ticks.put_nowait(None)
        assert await asyncio.to_thread(started.wait, 5)
        assert active == 1 and len(attempts) == 2 and waits.empty()
        # All four rendering slots stay available during refresh.
        for _ in range(4):
            assert service._slots.acquire(blocking=False)
        for _ in range(4):
            service._slots.release()
        assert (await asyncio.wait_for(_raw_request(app, query=_query().encode()), 2)).status_code == 200
        clock.now = 30
        assert (await asyncio.wait_for(_raw_request(app, query=_query().encode()), 2)).status_code == 503
        release.set()
        assert await asyncio.wait_for(waits.get(), 5) == 30
        assert service._snapshots["out.yaml"].acquired_at == 10
        assert (await _raw_request(app, query=_query().encode())).status_code == 200
        # A new interval starts after completion, with no queued catch-up round.
        assert len(attempts) == 2 and maximum == 1
        started.clear()
        release.clear()
        clock.now = 40
        ticks.put_nowait(None)
        assert await asyncio.to_thread(started.wait, 5)
        shutdown = asyncio.create_task(lifecycle.__aexit__(None, None, None))
        await asyncio.sleep(0)
        assert service._stop.is_set() and not shutdown.done()
        release.set()
        await asyncio.wait_for(shutdown, 5)
        assert len(attempts) == 3 and maximum == 1
        assert service._executor is None and service._refresh_executor is None

    try:
        asyncio.run(exercise())
    finally:
        release.set()


def test_cancelled_warmup_waits_for_actual_preparation_and_session_cleanup(tmp_path, monkeypatch):
    path, _ = _static(tmp_path)
    app = server.create_app(str(path))
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    prepare = ProviderLoaderService.prepare
    close = RunRemoteLoader.close

    def blocked(*args):
        entered.set()
        assert release.wait(10)
        return prepare(*args)

    def tracked_close(loader):
        close(loader)
        closed.set()

    monkeypatch.setattr(ProviderLoaderService, "prepare", blocked)
    monkeypatch.setattr(RunRemoteLoader, "close", tracked_close)

    async def exercise():
        async def startup():
            async with app.router.lifespan_context(app):
                pytest.fail("Cancelled warmup yielded")

        task = asyncio.create_task(startup())
        assert await asyncio.to_thread(entered.wait, 5)
        assert (await asyncio.wait_for(_raw_request(app, query=b"token=wrong"), 2)).status_code == 401
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not closed.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert closed.is_set()
        assert _service(app)._executor is None and _service(app)._refresh_executor is None

    try:
        asyncio.run(exercise())
    finally:
        release.set()


def test_shutdown_waits_for_cancelled_real_render_work(tmp_path, monkeypatch):
    path, _ = _static(tmp_path)
    app = server.create_app(str(path))
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    render = PreparedArtifact.render

    def blocked(*args):
        entered.set()
        assert release.wait(10)
        try:
            return render(*args)
        finally:
            finished.set()

    monkeypatch.setattr(PreparedArtifact, "render", blocked)

    async def exercise():
        lifecycle = app.router.lifespan_context(app)
        await lifecycle.__aenter__()
        request = asyncio.create_task(_raw_request(app, query=_query().encode()))
        assert await asyncio.to_thread(entered.wait, 5)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        shutdown = asyncio.create_task(lifecycle.__aexit__(None, None, None))
        await asyncio.sleep(0)
        assert not shutdown.done() and not finished.is_set()
        assert _service(app)._slots.acquire(blocking=False)
        _service(app)._slots.release()
        release.set()
        await asyncio.wait_for(shutdown, 5)
        assert finished.is_set()
        assert _service(app)._executor is None

    try:
        asyncio.run(exercise())
    finally:
        release.set()


def test_real_warm_http_has_no_source_io_decode_static_parse_or_workflow(tmp_path, monkeypatch):
    path, data = _static(tmp_path)
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    _, dynamic_data = _fixture(dynamic, "subio")
    data["provider"].extend([{**dynamic_data["provider"][0], "name": "dynamic", "file": "dynamic/nodes.yaml"}])
    data["artifact"].append({**dynamic_data["artifact"][0], "name": "dynamic.yaml", "providers": ["dynamic"]})
    data["ruleset"] = [{"name": "shared", "url": "https://synthetic.test/rules"}]
    _save(path, data)
    monkeypatch.setattr(RunRemoteLoader, "fetch", lambda *_args, **_kwargs: b"DOMAIN,example.test")

    def denied(*args, **kwargs):
        pytest.fail("HTTP reached resource loading, decoding, static parsing or WorkflowEngine")

    for target in (
        "subio_v2.workflow.engine.WorkflowEngine.__init__", "subio_v2.workflow.engine.WorkflowEngine.prepare",
        "subio_v2.workflow.publication.ArtifactPublisher.__init__",
        "subio_v2.workflow.uploader.GistBatchUploader.__init__",
    ):
        monkeypatch.setattr(target, denied)
    app = server.create_app(str(path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    running = server.uvicorn.Server(server.uvicorn.Config(
        app, host="127.0.0.1", port=port, access_log=False, log_config=None, log_level="critical"
    ))
    thread = threading.Thread(target=running.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not running.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert running.started

        with monkeypatch.context() as warmed:
            warmed.setattr(ProviderLoaderService, "_fetch_content", denied)
            warmed.setattr(ProviderLoaderService, "_decode_content", denied)
            warmed.setattr(ClashParser, "decode_source", denied)
            warmed.setattr(ClashParser, "parse_result", denied)
            warmed.setattr(SubioParser, "decode_source", denied)
            warmed.setattr(RunRemoteLoader, "__init__", denied)
            warmed.setattr(Path, "read_bytes", denied)
            warmed.setattr("builtins.open", denied)
            for target in (
                "subio_v2.workflow.rendering.prepare_resources", "subio_v2.rules.runtime.load_snippets",
                "subio_v2.rules.runtime.load_rulesets", "subio_v2.rules.parser.ClassicalRuleParser.parse_headless",
                "subio_v2.rules.parser.ClassicalRuleParser.parse_snippet",
                "jinja2.FileSystemLoader.get_source", "jinja2.FileSystemLoader.list_templates",
            ):
                warmed.setattr(target, denied)
            for route in ("out.yaml", "dynamic.yaml"):
                for credential in ("first", "second"):
                    query = urlencode({"token": TOKEN, "credential": credential, "url": "https://ignored.test"})
                    with urlopen(f"http://127.0.0.1:{port}/subscription/{route}?{query}", timeout=3) as response:
                        output = yaml.safe_load(response.read())
                    assert output["values"]["credential"] == credential
    finally:
        running.should_exit = True
        thread.join(10)
        listener.close()
    assert not thread.is_alive()

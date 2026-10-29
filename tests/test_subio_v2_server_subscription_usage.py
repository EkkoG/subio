"""Raw ASGI checks for usage ownership and GET/HEAD representation parity."""

import pytest
import yaml

pytest.importorskip("starlette")
pytest.importorskip("uvicorn")
pytest.importorskip("httpx")
from starlette.testclient import TestClient

from subio_v2 import server
from subio_v2.adapters.catalog import all_formats
from subio_v2.infrastructure import age
from subio_v2.infrastructure.remote import RemoteLoadError
from subio_v2.workflow.rendering import PreparedArtifact
from tests.test_subio_v2_remote_cache import Response, Session
from tests.test_subio_v2_server import TOKEN, _fixture, _headers, _query, _raw_request, _save, _service
from tests.test_subio_v2_server_snapshots import _clock
from tests.test_subio_v2_subscription_usage import NODE_CONTENT


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)


def _remote_fixture(tmp_path, monkeypatch, *, target="mihomo", info="upload=1;download=2;total=10;expire=0"):
    path, data = _fixture(tmp_path)
    data["provider"] = [{"name": "source", "type": "mihomo", "url": "https://example.test/source", "user_agent": "configured-agent"}]
    data["artifact"][0].update(type=target, on_duplicate_name="keep_first")
    if target == "sing-box":
        (tmp_path / "client.j2").write_text('{"outbounds": {{ nodes.outbounds() }}}')
    else:
        data["artifact"][0].pop("template")
    headers = {} if info is None else {"Subscription-Userinfo": info}
    headers.update({"ETag": "raw-header-canary", "Set-Cookie": "raw-header-canary", "Location": "https://example.test/raw-header-canary"})
    session = Session([Response(content=NODE_CONTENT, headers=headers)])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    return path, data, session


@pytest.mark.parametrize("target", [
    name for spec in all_formats() if spec.emitter_factory
    for name in (spec.name, *sorted(spec.aliases))
])
def test_actual_provider_aggregate_reaches_get_and_head_for_every_target(tmp_path, monkeypatch, target):
    path, data, session = _remote_fixture(tmp_path, monkeypatch, target=target)
    session.responses = iter([
        Response(content=NODE_CONTENT, headers={"Subscription-Userinfo": " upload=1.0; download=2e1; total=100; expire=0; unknown=raw-header-canary"}),
        Response(content=NODE_CONTENT, headers={"Subscription-Userinfo": "upload=3;download=4;total=0;expire=1700000000"}),
    ])
    data["provider"].extend([
        {**data["provider"][0], "name": "alias"},
        {"name": "second", "type": "mihomo", "url": "https://example.test/second"},
    ])
    data["artifact"][0]["providers"] = ["source", "alias", "second"]
    _save(path, data)
    app = server.create_app(str(path))
    with TestClient(app) as client:
        get = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode())
        head = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode(), "HEAD")
        assert get.status_code == head.status_code == 200
        assert get.content and head.content == b""
        assert head.headers == get.headers
        _headers(get)
        assert get.headers["subscription-userinfo"] == "upload=4; download=24; total=0; expire=1700000000"
        assert int(get.headers["content-length"]) == len(get.content)
        expected = _service(app)._snapshots["out.yaml"].artifact.render("out.yaml", {}).artifact_result.drafts[0].content
        assert get.content.decode() == expected
        assert "raw-header-canary" not in repr(get.headers)
        assert len(session.calls) == 2
    assert session.closed


@pytest.mark.parametrize("info,expected", [
    (None, None), ("unknown=raw-header-canary;upload=-1", None),
    ("upload=1;total=10;expire=0", "expire=0"),
    ("expire=1700000000", "expire=1700000000"),
])
def test_success_omits_unknown_usage_and_preserves_independent_expiry(tmp_path, monkeypatch, info, expected):
    path, data, _ = _remote_fixture(tmp_path, monkeypatch, info=info)
    _save(path, data)
    app = server.create_app(str(path))
    with TestClient(app) as client:
        for method in ("GET", "HEAD"):
            response = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode(), method)
            assert response.status_code == 200
            assert response.headers.get("subscription-userinfo") == expected
            assert "raw-header-canary" not in repr(response.headers)
            assert "set-cookie" not in response.headers
            if method == "HEAD":
                assert response.content == b""
            else:
                assert response.content


def test_age_get_decrypts_and_head_keeps_usage_and_representation_length(tmp_path, monkeypatch):
    path, data, _ = _remote_fixture(tmp_path, monkeypatch)
    secret, public = age.generate_x25519_keypair()
    data["artifact"][0]["age_public_key"] = public
    _save(path, data)
    encrypt = age.encrypt_bytes
    ciphertexts = []

    def capture(*args, **kwargs):
        ciphertext = encrypt(*args, **kwargs)
        ciphertexts.append(ciphertext)
        return ciphertext

    monkeypatch.setattr(age, "encrypt_bytes", capture)
    app = server.create_app(str(path))
    with TestClient(app) as client:
        get = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode())
        head = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode(), "HEAD")
        assert get.status_code == head.status_code == 200
        assert get.content.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----")
        assert head.content == b""
        assert {key: value for key, value in head.headers.items() if key != "content-length"} == {
            key: value for key, value in get.headers.items() if key != "content-length"
        }
        assert get.headers["subscription-userinfo"] == "upload=1; download=2; total=10; expire=0"
        assert len(ciphertexts) == 2
        assert int(get.headers["content-length"]) == len(ciphertexts[0]) == len(get.content)
        assert int(head.headers["content-length"]) == len(ciphertexts[1])
        decrypted = age.decrypt_bytes(get.content, secret)
        assert yaml.safe_load(decrypted)["proxies"][0]["name"] == "upstream"
        # Age padding can change length; freeze real ciphertext for fixture parity.
        monkeypatch.setattr(age, "encrypt_bytes", lambda *_args, **_kwargs: get.content)
        frozen_head = client.portal.call(_raw_request, app, b"/subscription/out.yaml", _query().encode(), "HEAD")
        assert frozen_head.content == b"" and frozen_head.headers == get.headers


@pytest.mark.parametrize("case,status", [
    ("encoding", 400), ("oversized", 413), ("token", 401), ("route", 404),
    ("parameter", 400), ("missing", 400), ("conversion", 422),
    ("not_ready", 503), ("expired", 503), ("busy", 503),
    ("template", 500), ("upstream", 502),
])
def test_raw_head_error_has_get_status_headers_and_zero_sent_bytes(tmp_path, monkeypatch, case, status):
    path, data = _fixture(tmp_path)
    data["provider"].extend([
        {"name": "usage", "type": "mihomo", "url": "https://example.test/usage"},
        {"name": "unready", "type": "mihomo", "file": "absent.yaml"},
    ])
    data["artifact"][0]["providers"].append("usage")
    data["artifact"].append({"name": "unready.yaml", "type": "mihomo", "providers": ["unready"]})
    if case == "conversion":
        data["artifact"][0]["params"]["port"]["min"] = 0
    if case == "template":
        (tmp_path / "client.j2").write_text("{{ unknown_callable() }}")
    _save(path, data)
    session = Session([Response(content=NODE_CONTENT, headers={"Subscription-Userinfo": "upload=1;download=2;total=10"})])
    monkeypatch.setattr("subio_v2.infrastructure.remote.requests.Session", lambda: session)
    clock = _clock(monkeypatch)
    app = server.create_app(str(path), refresh_interval=10, max_snapshot_age=30)
    with TestClient(app) as client:
        service = _service(app)
        route, query = b"/subscription/out.yaml", _query().encode()
        if case == "encoding":
            query = b"%"
        elif case == "oversized":
            query = b"x" * 8193
        elif case == "token":
            query = b""
        elif case == "route":
            route = b"/subscription/unknown"
        elif case == "parameter":
            query = _query(port="bad").encode()
        elif case == "missing":
            query = ("token=" + TOKEN).encode()
        elif case == "conversion":
            query = _query(port="0").encode()
        elif case == "not_ready":
            route = b"/subscription/unready.yaml"
        elif case == "expired":
            clock.now = 30
        elif case == "busy":
            for _ in range(4):
                assert service._slots.acquire(blocking=False)
        elif case == "upstream":
            def fail(*args):
                raise RemoteLoadError("upstream-exception-canary")
            monkeypatch.setattr(PreparedArtifact, "render", fail)
        try:
            get = client.portal.call(_raw_request, app, route, query)
            head = client.portal.call(_raw_request, app, route, query, "HEAD")
            assert get.status_code == head.status_code == status
            assert head.content == b"" and get.content
            assert head.headers == get.headers
            assert int(head.headers["content-length"]) == len(get.content)
            assert "subscription-userinfo" not in get.headers
            assert "upstream-exception-canary" not in get.content.decode()
            _headers(head)
        finally:
            if case == "busy":
                for _ in range(4):
                    service._slots.release()

import asyncio
import copy
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import quote, unquote_to_bytes, urlencode
from urllib.request import urlopen

import pytest
import toml
import yaml

pytest.importorskip("starlette", reason="HTTP contracts require the server extra")
pytest.importorskip("uvicorn", reason="HTTP contracts require the server extra")
pytest.importorskip("httpx", reason="HTTP test transport requires dev dependencies")
from starlette.testclient import TestClient

from subio_v2 import server
from subio_v2.infrastructure import age
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.workflow.artifacts import ArtifactGenerationService
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.providers import ProviderLoaderService


TOKEN = "synthetic_service_canary_0123456789"
SECRET = "synthetic_request_canary"


@pytest.fixture(autouse=True)
def service_token(monkeypatch):
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)


def _fixture(tmp_path, family="mihomo", serialization="yaml"):
    node = {
        "name": "{{ params.name }}", "type": "socks5",
        "server": "{{ params.host }}", "port": "{{ params.port }}",
        "username": "{{ params.username }}", "password": "{{ params.credential }}",
    }
    document = {"version": 2, "nodes": [node]} if family == "subio" else {"proxies": [node]}
    source = tmp_path / ("nodes." + serialization)
    if serialization == "toml":
        source.write_text(toml.dumps(document))
    elif serialization in {"json", "json5"}:
        source.write_text(json.dumps(document))
    else:
        source.write_text(yaml.safe_dump(document))
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\n"
        "values: {{ params | tojson }}\n"
    )
    params = {
        "name": {"type": "string", "default": "default-name"},
        "host": {"type": "string", "default": "proxy.example.test"},
        "port": {"type": "integer", "default": 1080, "min": 1, "max": 65535},
        "username": {"type": "string", "default": "synthetic-user"},
        "credential": {"type": "string", "required": True},
        "enabled": {"type": "boolean", "default": False},
    }
    data = {
        "provider": [{"name": "source", "type": family, "file": source.name, "parameterized": True}],
        "artifact": [{"name": "out.yaml", "type": "mihomo", "template": "client.j2",
                      "providers": ["source"], "params": params}],
    }
    path = tmp_path / "config.json"
    _save(path, data)
    return path, data


def _save(path, data):
    path.write_text(json.dumps(data))


def _query(**values):
    return urlencode({"token": TOKEN, "credential": SECRET, **values})


def _headers(response):
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert not any(name in response.headers for name in (
        "etag", "last-modified", "location", "access-control-allow-origin"
    ))


def _service(app):
    return app.user_middleware[0].kwargs["service"]


async def _raw_request(app, path=b"/subscription/out.yaml", query=b"", method="GET", *, disconnect=False):
    messages = []
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": unquote_to_bytes(path).decode("utf-8", errors="replace"),
        "raw_path": path, "query_string": query, "root_path": "", "headers": [],
        "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 8000),
    }

    async def receive():
        return {"type": "http.disconnect"} if disconnect else {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(item for item in messages if item["type"] == "http.response.start")
    body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
    return SimpleNamespace(status_code=start["status"], content=body,
                           headers={name.decode(): value.decode() for name, value in start["headers"]})


@pytest.mark.parametrize("family,serialization", [
    ("mihomo", "yaml"), ("clash-meta", "yaml"), ("clash", "yaml"),
    ("subio", "toml"), ("subio", "json"), ("subio", "json5"), ("subio", "yaml"),
])
def test_headerless_get_decodes_once_and_renders_both_families(tmp_path, monkeypatch, family, serialization):
    path, _ = _fixture(tmp_path, family, serialization)
    special = ' leading + & = % # " 雪 {{ 7 * 7 }} {{ params.host }} proxies: [injection] '
    calls = []
    factory = WorkflowEngine.for_render

    def capture(config_path, config, route, parameters):
        calls.append(dict(parameters))
        assert "token" not in parameters
        with pytest.raises(TypeError):
            parameters["host"] = "mutation"
        return factory(config_path, config, route, parameters)

    monkeypatch.setattr(WorkflowEngine, "for_render", capture)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query(credential=special, port="+1081", enabled="true"))
        assert response.status_code == 200
        _headers(response)
        assert response.headers["content-type"] == "application/yaml"
        assert response.headers["content-disposition"] == "attachment"
        output = yaml.safe_load(response.text)
        assert len(output["proxies"]) == 1
        assert output["proxies"][0]["password"] == special
        assert output["proxies"][0]["port"] == 1081
        assert output["values"]["enabled"] is True
        assert output["values"] == calls[0]
        assert TOKEN not in response.text
        response = client.get("/subscription/out.yaml?" + _query(credential="%2B%26%3D%25%23"))
        assert yaml.safe_load(response.text)["proxies"][0]["password"] == "%2B%26%3D%25%23"
        response = client.get("/subscription/out.yaml?token=" + TOKEN + "&credential=a+b%2Bc")
        assert yaml.safe_load(response.text)["values"]["credential"] == "a b+c"
        response = client.get("/subscription/out.yaml?%74oken=" + TOKEN + "&credential=x")
        assert response.status_code == 200


@pytest.mark.parametrize("token", [None, "", "x" * 31, "x" * 129, "x" * 31 + "é", "x" * 32 + "\n", "x" * 32 + "+"])
def test_startup_token_validation_is_fixed_and_precedes_config_loading(tmp_path, monkeypatch, token):
    if token is None:
        monkeypatch.delenv("SUBIO_RENDER_TOKEN")
    else:
        monkeypatch.setenv("SUBIO_RENDER_TOKEN", token)
    monkeypatch.setattr(server.ConfigLoader, "load", lambda *_: pytest.fail("Read config before token validation"))
    with pytest.raises(server.ServerConfigurationError) as caught:
        server.create_app(str(tmp_path / "missing"))
    assert str(caught.value) == "SUBIO_RENDER_TOKEN is missing or invalid"
    if token:
        assert token not in repr(caught.value)


@pytest.mark.parametrize("query", [
    b"", b"credential=x", b"token=", b"token=wrong", b"token=%C3%A9",
    b"token=" + TOKEN.encode() + b"&token=" + TOKEN.encode(),
    b"token=" + TOKEN.encode() + b"&%74oken=" + TOKEN.encode(),
    b"%74oken=" + TOKEN.encode() + b"&t%6fken=" + TOKEN.encode(),
])
def test_authentication_precedes_route_normalization_admission_and_all_input_io(tmp_path, monkeypatch, query):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))

    def denied(*args, **kwargs):
        pytest.fail("Protected work occurred before authentication")

    class Routes:
        get = denied

    class Slots:
        acquire = denied

    _service(app).routes = Routes()
    _service(app)._slots = Slots()
    monkeypatch.setattr(server, "normalize_parameters", denied)
    monkeypatch.setattr(WorkflowEngine, "for_render", denied)
    for name in ("load_snippets", "load_rulesets", "RunRemoteLoader"):
        monkeypatch.setattr("subio_v2.workflow.engine." + name, denied)
    monkeypatch.setattr(ProviderLoaderService, "_fetch_content", denied)
    with TestClient(app, cookies={"token": TOKEN}) as client:
        response = client.get("/unknown?" + query.decode(), headers={"Authorization": TOKEN})
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}
        _headers(response)


@pytest.mark.parametrize("path,query,status", [
    (b"/subscription/out.yaml", b"token=%", 400),
    (b"/subscription/out.yaml", b"token=%GG", 400),
    (b"/subscription/out.yaml", b"token=%FF", 400),
    (b"/subscription/out.yaml", b"%FF=value", 400),
    (b"/subscription/%FF", b"", 400),
    (b"/subscription/%", b"", 400),
    (b"/subscription/out.yaml", b"token=%C0%AF", 400),
    (b"/subscription/out.yaml", b"token=wrong&" + b"&".join([b"x=1"] * 33), 413),
    (b"/" + b"x" * 8192, b"", 413),
    (b"/subscription/out.yaml", b"x=" + b"x" * 8192, 413),
])
def test_raw_limits_and_encoding_are_checked_before_auth(tmp_path, monkeypatch, path, query, status):
    config_path, _ = _fixture(tmp_path)
    app = server.create_app(str(config_path))
    monkeypatch.setattr(server.secrets, "compare_digest", lambda *_: pytest.fail("Auth ran before raw checks"))
    with TestClient(app):
        response = asyncio.run(_raw_request(app, path, query))
    assert response.status_code == status
    _headers(response)


@pytest.mark.parametrize("suffix,status", [
    ("&unknown=x", 400), ("&template=other.j2", 400), ("&file=/etc/passwd", 400),
    ("&url=https://other.test", 400), ("&user=other", 400), ("&type=surge", 400),
    ("&host=a&%68ost=b", 400), ("&port=1.5", 400), ("&port=true", 400),
    ("&port=0", 400), ("&port=65536", 400), ("&enabled=TRUE", 400),
    ("&enabled=1", 400), ("&host=%00", 400), ("&host=%0A", 400),
    ("&host=%E2%80%A8", 400), ("&host=%E2%80%A9", 400),
    ("&host=", 400), ("&host=" + "x" * 1025, 413),
    ("&host=" + "%E9%9B%AA" * 342, 413),
    ("&credential[]=object", 400), ("&credential%5B0%5D=array", 400),
])
def test_semantic_rejections_precede_construction_and_loading(tmp_path, monkeypatch, suffix, status):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    monkeypatch.setattr(WorkflowEngine, "for_render", lambda *_: pytest.fail("Constructed invalid render"))
    with TestClient(app) as client:
        response = client.get("/subscription/out.yaml?" + _query() + suffix)
        assert response.status_code == status
        _headers(response)
        assert SECRET not in response.text and TOKEN not in response.text
        response = client.get("/subscription/out.yaml?token=" + TOKEN)
        assert response.status_code == 400


def test_exact_raw_and_decoded_value_boundaries(tmp_path):
    path, data = _fixture(tmp_path)
    params = data["artifact"][0]["params"]
    params["credential"] = {"type": "string", "required": True, "allow_empty": True}
    for index in range(26):
        params["field_" + str(index)] = {"type": "string", "default": "default"}
    assert len(params) == 32
    _save(path, data)
    app = server.create_app(str(path))
    with TestClient(app) as client:
        response = client.get("/subscription/out.yaml?" + _query(credential="雪" * 341 + "x"))
        assert response.status_code == 200
        fields = {name: "x" for name in params}
        fields.update(port="1080", enabled="false", credential="")
        response = client.get("/subscription/out.yaml?" + _query(**fields))
        assert response.status_code == 200
        response = asyncio.run(_raw_request(app, b"/" + b"x" * 8191))
        assert response.status_code == 401
        response = asyncio.run(_raw_request(app, b"/" + b"x" * 8192))
        assert response.status_code == 413


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "POST", "PUT", "DELETE", "TRACE", "PATCH"])
def test_every_non_get_method_is_fixed_405_without_framework_redirects_or_io(tmp_path, monkeypatch, method):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    monkeypatch.setattr(WorkflowEngine, "for_render", lambda *_: pytest.fail("Constructed non-GET render"))
    with TestClient(app) as client:
        response = client.request(method, "/subscription/out.yaml?" + _query(), follow_redirects=False)
        assert response.status_code == 405
        _headers(response)
        if method != "HEAD":
            assert response.json() == {"error": "method_not_allowed"}
        response = client.request(method, "/subscription/out.yaml?token=wrong")
        assert response.status_code == 401


@pytest.mark.parametrize("target", [
    "/", "/subscription", "/subscription/", "/subscription/out.yaml/",
    "/subscription/unknown", "/subscription/OUT.yaml", "/subscription/out.yaml%0A",
    "/render/demo", "/docs", "/openapi.json",
    "/subscription/%2E%2E%2Fconfig.json", "/subscription/%2Fetc%2Fpasswd",
    "/subscription/..%5Cconfig.json", "/subscription/%252E%252E%252Fconfig.json",
])
def test_unknown_paths_are_safe_404_with_no_enumeration_or_redirect(tmp_path, monkeypatch, target):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    monkeypatch.setattr(WorkflowEngine, "for_render", lambda *_: pytest.fail("Constructed unknown render"))
    with TestClient(app) as client:
        response = client.get(target + "?" + _query(), follow_redirects=False)
        assert response.status_code == 404
        assert response.json() == {"error": "not_found"}
        _headers(response)


@pytest.mark.parametrize("file_name", ["out.yaml", "\u5ba2\u6237 +%#?.yaml", "%2F.yaml"])
def test_existing_artifact_needs_no_params_or_render_and_matches_decoded_filename(tmp_path, file_name):
    path, data = _fixture(tmp_path)
    data["provider"][0].pop("parameterized")
    data["artifact"][0].pop("params")
    data["artifact"][0]["name"] = file_name
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump({"proxies": [{
        "name": "static", "type": "socks5", "server": "example.test", "port": 1080,
    }]}))
    _save(path, data)
    target = "/subscription/" + quote(file_name, safe="")
    with TestClient(server.create_app(str(path))) as client:
        response = client.get(target, params={"token": TOKEN})
        assert response.status_code == 200
        assert yaml.safe_load(response.text)["proxies"][0]["name"] == "static"
        assert yaml.safe_load(response.text)["values"] == {}
        assert response.headers["content-disposition"] == "attachment"
        assert client.get(target, params={"token": TOKEN, "unknown": "value"}).status_code == 400
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("batch", [False, True])
def test_expanded_filename_selects_one_configured_user(tmp_path, family, batch):
    path, data = _fixture(tmp_path, family)
    artifact = data["artifact"][0]
    artifact["name"] = "user-{user}.yaml"
    artifact.update({"users": ["alice", "bob"]} if batch else {"user": "alice"})
    artifact["params"]["user"] = {"type": "string", "default": "unrelated-template-value"}
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    nodes = document["nodes" if family == "subio" else "proxies"]
    nodes[0]["users"] = {
        "alice": {"username": "alice-static", "password": "alice-{{ params.credential }}"},
        "bob": {"username": "bob-static", "password": "bob-{{ params.credential }}"},
    }
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        for user in (["alice", "bob"] if batch else ["alice"]):
            response = client.get("/subscription/user-" + user + ".yaml?" + _query(user="bob"))
            assert response.status_code == 200
            output = yaml.safe_load(response.text)
            assert len(output["proxies"]) == 1
            assert output["proxies"][0]["username"] == user + "-static"
            assert output["proxies"][0]["password"] == user + "-" + SECRET
            assert output["values"]["user"] == "bob"
        for file_name in (["user-{user}.yaml", "user-mallory.yaml"] + ([] if batch else ["user-bob.yaml"])):
            response = client.get("/subscription/" + quote(file_name, safe="") + "?" + _query())
            assert response.status_code == 404
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("name", ["../out.yaml", "/out.yaml", "a/b.yaml", "a\\b.yaml", ".", ".."])
def test_service_rejects_configured_paths_instead_of_filenames(tmp_path, name):
    path, data = _fixture(tmp_path)
    data["artifact"][0]["name"] = name
    _save(path, data)
    with pytest.raises(server.ServerConfigurationError, match="filenames"):
        server.create_app(str(path))


def test_startup_snapshot_and_secret_are_read_once(tmp_path, monkeypatch):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    path.write_text("invalid changed configuration")
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", "changed_token_value_0123456789012345")
    monkeypatch.setattr(server.ConfigLoader, "load", lambda *_: pytest.fail("Reread startup config"))
    with TestClient(app) as client:
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
        assert client.get("/subscription/out.yaml?" + _query(token="changed_token_value_0123456789012345")).status_code == 401


@pytest.mark.parametrize("family", ["mihomo", "subio"])
def test_control_token_is_excluded_but_node_token_can_bind(tmp_path, family):
    path, data = _fixture(tmp_path, family)
    params = data["artifact"][0]["params"]
    params["node_token"] = {"type": "string", "required": True}
    node = {"name": "tuic", "type": "tuic", "server": "proxy.example.test", "port": 443,
            "token": "{{ params.node_token }}"}
    if family == "subio":
        node["version"] = 4
        document = {"version": 2, "nodes": [node]}
    else:
        document = {"proxies": [node]}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query(node_token="synthetic_node_token"))
        assert response.status_code == 200
        output = yaml.safe_load(response.text)
        assert output["proxies"][0]["token"] == "synthetic_node_token"
        assert "token" not in output["values"]
        assert TOKEN not in response.text


@pytest.mark.parametrize("target,media", [("mihomo", "application/yaml"), ("stash", "application/yaml"),
                                         ("sing-box", "application/json"), ("surge", "text/plain; charset=utf-8"),
                                         ("v2rayn", "text/plain; charset=utf-8"), ("dae", "text/plain; charset=utf-8")])
def test_success_media_and_attachment_use_configured_target(tmp_path, target, media):
    path, data = _fixture(tmp_path)
    data["artifact"][0]["type"] = target
    data["artifact"][0]["name"] = "operator-chosen-name"
    if target == "sing-box":
        (tmp_path / "client.j2").write_text('{"outbounds": {{ nodes.outbounds() }}}')
    else:
        data["artifact"][0].pop("template")
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/operator-chosen-name?" + _query())
        assert response.status_code == 200
        _headers(response)
        assert response.headers["content-type"] == media
        assert response.headers["content-disposition"] == "attachment"
        if target == "sing-box":
            assert len(response.json()["outbounds"]) == 1


@pytest.mark.parametrize("global_key", [False, True])
def test_age_content_and_fixed_user_use_existing_preparation(tmp_path, global_key):
    path, data = _fixture(tmp_path, "subio")
    secret_key, public_key = age.generate_x25519_keypair()
    if global_key:
        data["age_public_key"] = public_key
    else:
        data["artifact"][0]["age_public_key"] = public_key
    data["artifact"][0]["user"] = "fixed-user"
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    document["nodes"][0]["users"] = {"fixed-user": {"username": "fixed-username"}}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query())
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        _headers(response)
        decrypted = age.decrypt_bytes(response.content, secret_key).decode()
        assert yaml.safe_load(decrypted)["proxies"][0]["username"] == "fixed-username"
        assert SECRET not in response.text and TOKEN not in response.text


@pytest.mark.parametrize("family", ["mihomo", "subio"])
def test_parse_and_target_errors_reject_partial_output_despite_static_optouts(tmp_path, family, capsys):
    path, data = _fixture(tmp_path, family)
    data["allow_conversion_errors"] = True
    data["artifact"][0]["allow_conversion_errors"] = True
    data["artifact"][0]["allow_empty"] = True
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    nodes = document["nodes" if family == "subio" else "proxies"]
    nodes.append({"name": SECRET, "type": "socks5", "server": "invalid.example", "port": 0})
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query())
        assert response.status_code == 422
        assert response.json() == {"error": "conversion_rejected"}
        assert SECRET not in response.text and "proxies" not in response.text
        _headers(response)
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


@pytest.mark.parametrize("family", ["mihomo", "subio"])
def test_target_encoding_rejection_is_422_before_a_draft_exists(tmp_path, family):
    path, data = _fixture(tmp_path, family)
    data["artifact"][0]["type"] = "v2rayn"
    data["artifact"][0].pop("template")
    data["artifact"][0]["allow_conversion_errors"] = True
    data["allow_conversion_errors"] = True
    _save(path, data)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query(host="good.example#fragment"))
        assert response.status_code == 422
        assert response.json() == {"error": "conversion_rejected"}
        _headers(response)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("fixed_user", [False, True])
def test_direct_and_fixed_user_port_validation_returns_422_and_recovers(
    tmp_path, monkeypatch, capsys, caplog, family, fixed_user
):
    path, data = _fixture(tmp_path, family)
    data["allow_conversion_errors"] = True
    artifact = data["artifact"][0]
    artifact["allow_conversion_errors"] = True
    artifact["params"]["port"] = {"type": "integer", "required": True}
    source = tmp_path / "nodes.yaml"
    document = yaml.safe_load(source.read_text())
    nodes = document["nodes" if family == "subio" else "proxies"]
    if fixed_user:
        artifact["user"] = "fixed"
        nodes[0]["port"] = 1080
        nodes[0]["users"] = {"fixed": {"port": "{{ params.port }}"}}
    nodes.append({"name": "shared", "type": "socks5", "server": "shared.test", "port": 1080})
    source.write_text(yaml.safe_dump(document))
    _save(path, data)
    staged = []
    original_stage = ArtifactGenerationService._stage

    def stage(*args):
        staged.append(True)
        return original_stage(*args)

    monkeypatch.setattr("subio_v2.workflow.artifacts.ArtifactGenerationService._stage", stage)
    with caplog.at_level(logging.DEBUG), TestClient(server.create_app(str(path))) as client:
        for port in (1081, 0, 1082):
            staged.clear()
            response = client.get("/subscription/out.yaml?" + _query(port=port))
            _headers(response)
            if port == 0:
                assert response.status_code == 422
                assert response.json() == {"error": "conversion_rejected"}
                assert staged == []
                assert SECRET not in response.text and TOKEN not in response.text
            else:
                assert response.status_code == 200
                proxies = yaml.safe_load(response.text)["proxies"]
                assert [node["port"] for node in proxies] == [port, 1080]
                assert staged == [True]
    assert not (tmp_path / "dist").exists()
    captured = capsys.readouterr()
    application_logs = "\n".join(record.getMessage() for record in caplog.records if record.name != "httpx")
    assert all(value not in captured.out + captured.err + application_logs for value in (TOKEN, SECRET))


@pytest.mark.parametrize("failure,status", [
    ("provider", 502), ("ruleset", 502), ("missing_file", 500), ("template", 500), ("internal", 500),
])
def test_actual_failure_paths_are_sanitized_and_recover(tmp_path, monkeypatch, capsys, caplog, failure, status):
    path, data = _fixture(tmp_path)
    data["provider"].append({"name": "remote", "type": "mihomo", "url": "https://upstream.test/static"})
    data["artifact"][0]["providers"].append("remote")
    if failure == "ruleset":
        data["ruleset"] = [{"name": "static", "url": "https://upstream.test/rules"}]
    _save(path, data)
    working = {"value": False}

    def fetch(loader, url, *, headers=None):
        if not working["value"] and failure in {"provider", "ruleset"}:
            raise server.RemoteLoadError(SECRET + TOKEN)
        if url.endswith("rules"):
            return b"DOMAIN,example.test"
        return b"proxies: [{name: static, type: socks5, server: static.test, port: 1080}]"

    monkeypatch.setattr(RunRemoteLoader, "fetch", fetch)
    original = WorkflowEngine.for_render

    def construct(*args):
        engine = original(*args)
        if not working["value"] and failure == "internal":
            raise RuntimeError(SECRET + TOKEN)
        return engine

    monkeypatch.setattr(WorkflowEngine, "for_render", construct)
    original_source = (tmp_path / "nodes.yaml").read_text()
    original_template = (tmp_path / "client.j2").read_text()
    if failure == "missing_file":
        (tmp_path / "nodes.yaml").unlink()
    if failure == "template":
        (tmp_path / "client.j2").write_text("{{ " + SECRET + " }}")
    with caplog.at_level(logging.DEBUG), TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.yaml?" + _query())
        assert response.status_code == status
        _headers(response)
        assert response.json() == {"error": "upstream_error" if status == 502 else "internal_error"}
        working["value"] = True
        (tmp_path / "nodes.yaml").write_text(original_source)
        (tmp_path / "client.j2").write_text(original_template)
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
    captured = capsys.readouterr()
    # HTTPX is the test client, and deliberately logs its own outgoing URL at INFO.
    application_logs = "\n".join(record.getMessage() for record in caplog.records if record.name != "httpx")
    assert all(value not in captured.out + captured.err + application_logs for value in (TOKEN, SECRET))


def test_request_results_are_not_persisted_or_forwarded_upstream(tmp_path, monkeypatch, capsys):
    path, data = _fixture(tmp_path)
    data["remote"] = {"cache": {"enabled": True}}
    data["provider"].append({"name": "remote", "type": "mihomo", "url": "https://upstream.test/static", "user_agent": "static-agent"})
    data["artifact"][0]["providers"].append("remote")
    data["uploader"] = [{"name": "denied", "type": "gist", "id": "synthetic", "token": "synthetic-uploader"}]
    data["artifact"][0]["upload"] = [{"to": "denied"}]
    _save(path, data)
    upstream, cache = [], []

    def get(session, url, **kwargs):
        upstream.append((url, kwargs))
        return SimpleNamespace(status_code=200, headers={}, raise_for_status=lambda: None,
                               content=b"proxies: [{name: static, type: socks5, server: static.test, port: 1080}]")

    def denied(*args, **kwargs):
        pytest.fail("Render attempted publication, report, manifest or upload")

    monkeypatch.setattr("requests.Session.get", get)
    monkeypatch.setattr(RunRemoteLoader, "_read_disk", lambda *_: None)
    monkeypatch.setattr(RunRemoteLoader, "_write_disk", lambda loader, key, result: cache.append((key, result.content)))
    for target in ("subio_v2.workflow.engine.ArtifactPublisher.commit", "subio_v2.workflow.engine.queue_upload_requests",
                   "subio_v2.workflow.engine.apply_manifest", "subio_v2.workflow.engine.GistBatchUploader.flush",
                   "subio_v2.workflow.report.build_report", "subio_v2.workflow.engine.WorkflowEngine.run"):
        monkeypatch.setattr(target, denied)
    before = {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}
    with TestClient(server.create_app(str(path))) as client:
        for credential in (SECRET, "second_request_canary"):
            response = client.get("/subscription/out.yaml?" + _query(credential=credential))
            assert response.status_code == 200
            assert yaml.safe_load(response.text)["values"]["credential"] == credential
    assert len(upstream) == len(cache) == 2
    assert all(TOKEN not in repr(value) and SECRET not in repr(value) for value in (upstream, cache))
    assert all(item[0] == "https://upstream.test/static" for item in upstream)
    assert upstream[0][1]["headers"] == {"User-Agent": "static-agent"}
    assert before == {item.relative_to(tmp_path) for item in tmp_path.rglob("*")}
    assert not (tmp_path / "dist").exists()
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err and SECRET not in captured.out + captured.err


def test_parallel_routes_have_isolated_defaults_parameters_and_logger_lifetime(tmp_path, monkeypatch):
    path, data = _fixture(tmp_path)
    second = copy.deepcopy(data["artifact"][0])
    second["name"] = "second.yaml"
    second["params"]["port"] = {"type": "integer", "default": 9080, "min": 9000, "max": 9999}
    second["params"]["name"]["default"] = "other-default"
    data["artifact"].append(second)
    _save(path, data)
    barrier = threading.Barrier(2)
    load = ProviderLoaderService.load

    def parallel_load(*args, **kwargs):
        assert logger._quiet
        barrier.wait(timeout=5)
        return load(*args, **kwargs)

    monkeypatch.setattr(ProviderLoaderService, "load", parallel_load)
    previous = logger._quiet
    with TestClient(server.create_app(str(path))) as client:
        assert logger._quiet
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(client.get, "/subscription/out.yaml?" + _query(credential="first-secret"))
            second = pool.submit(client.get, "/subscription/second.yaml?" + _query(credential="second-secret"))
            responses = [first.result(timeout=10), second.result(timeout=10)]
        for response, name, port, credential in zip(responses, ("default-name", "other-default"), (1080, 9080), ("first-secret", "second-secret")):
            assert response.status_code == 200
            output = yaml.safe_load(response.text)
            assert output["proxies"][0]["name"] == name
            assert output["proxies"][0]["port"] == port
            assert output["proxies"][0]["password"] == credential
        assert logger._quiet
        monkeypatch.setattr(ProviderLoaderService, "load", load)
        assert client.get("/subscription/second.yaml?" + _query(port="1080")).status_code == 400
        assert client.get("/subscription/out.yaml?" + _query()).status_code == 200
    assert logger._quiet is previous


def test_four_actual_workers_hold_slots_after_disconnect_and_cancellation_then_recover(tmp_path, monkeypatch):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    started = threading.Barrier(5)
    release = threading.Event()
    exited = threading.Event()
    lock = threading.Lock()
    counts = {"active": 0, "exits": 0, "max": 0}
    service = _service(app)
    original = service._render

    def blocked(*args):
        with lock:
            counts["active"] += 1
            counts["max"] = max(counts["max"], counts["active"])
        try:
            started.wait(timeout=10)
            assert release.wait(timeout=10)
            return original(*args)
        finally:
            with lock:
                counts["active"] -= 1
                counts["exits"] += 1
                if counts["exits"] == 4:
                    exited.set()

    monkeypatch.setattr(service, "_render", blocked)

    async def exercise():
        async with app.router.lifespan_context(app):
            tasks = [asyncio.create_task(_raw_request(app, query=_query(credential=str(index)).encode(), disconnect=True)) for index in range(4)]
            try:
                await asyncio.to_thread(started.wait, 5)
                overflow = await _raw_request(app, query=_query().encode())
                assert overflow.status_code == 503
                _headers(overflow)
                # The event loop remains responsive while four synchronous threads block.
                assert (await _raw_request(app, query=b"token=wrong")).status_code == 401
                assert (await _raw_request(app, query=_query(port="0").encode())).status_code == 400
                tasks[0].cancel()
                with pytest.raises(asyncio.CancelledError):
                    await tasks[0]
                assert (await _raw_request(app, query=_query().encode())).status_code == 503
                assert counts["active"] == counts["max"] == 4
                release.set()
                results = await asyncio.wait_for(asyncio.gather(*tasks[1:]), timeout=10)
                assert all(result.status_code == 200 for result in results)
                assert await asyncio.to_thread(exited.wait, 5)
                monkeypatch.setattr(service, "_render", original)
                # The cancelled request's worker must also finish before all four slots recover.
                for _ in range(4):
                    assert service._slots.acquire(blocking=False)
                for _ in range(4):
                    service._slots.release()
                response = await _raw_request(app, query=_query().encode())
                assert response.status_code == 200
                assert counts["max"] == 4
            finally:
                release.set()
                await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(exercise())


def test_real_loopback_disconnects_keep_four_running_workers_admitted(tmp_path, monkeypatch):
    path, _ = _fixture(tmp_path)
    app = server.create_app(str(path))
    service = _service(app)
    original = service._render
    started = threading.Barrier(5)
    release = threading.Event()
    finished = threading.Barrier(5)

    def blocked(*args):
        started.wait(timeout=10)
        assert release.wait(timeout=10)
        try:
            return original(*args)
        finally:
            finished.wait(timeout=10)

    monkeypatch.setattr(service, "_render", blocked)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    config = server.uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False,
                                   log_config=None, log_level="critical")
    running = server.uvicorn.Server(config)
    thread = threading.Thread(target=running.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not running.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert running.started
        for _ in range(4):
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            request = "GET /subscription/out.yaml?" + _query() + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            connection.sendall(request.encode("ascii"))
            connection.close()
        started.wait(timeout=5)
        with pytest.raises(HTTPError) as caught:
            urlopen(f"http://127.0.0.1:{port}/subscription/out.yaml?" + _query(), timeout=2)
        assert caught.value.code == 503
        _headers(caught.value)
        assert json.loads(caught.value.read()) == {"error": "busy"}
        release.set()
        finished.wait(timeout=5)
        monkeypatch.setattr(service, "_render", original)
        with urlopen(f"http://127.0.0.1:{port}/subscription/out.yaml?" + _query(), timeout=2) as response:
            assert response.status == 200
            assert yaml.safe_load(response.read())["values"]["credential"] == SECRET
    finally:
        release.set()
        running.should_exit = True
        thread.join(timeout=10)
        listener.close()
    assert not thread.is_alive()


def test_serve_disables_framework_logs_and_uses_loopback_without_reload(tmp_path, monkeypatch, capsys):
    path, _ = _fixture(tmp_path)
    calls = []
    names = ("uvicorn", "uvicorn.error", "uvicorn.access", "starlette")
    before = [logging.getLogger(name).disabled for name in names]

    def run(app, **kwargs):
        assert logger._quiet
        assert all(logging.getLogger(name).disabled for name in names)
        logging.getLogger("uvicorn.error").critical(TOKEN + SECRET)
        logger.error(TOKEN + SECRET)
        calls.append(kwargs)

    monkeypatch.setattr(server.uvicorn, "run", run)
    assert server.serve(str(path)) == 0
    assert calls == [{"host": "127.0.0.1", "port": 8000, "access_log": False,
                      "log_config": None, "log_level": "critical", "server_header": False, "proxy_headers": False}]
    assert [logging.getLogger(name).disabled for name in names] == before
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err and SECRET not in captured.out + captured.err


def test_serve_startup_errors_never_echo_secret_configuration(tmp_path, monkeypatch, capsys):
    path, _ = _fixture(tmp_path)
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", SECRET)
    assert server.serve(str(path)) == 1
    assert "SUBIO_RENDER_TOKEN is missing or invalid" in capsys.readouterr().out
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    path.write_text(SECRET + TOKEN)
    assert server.serve(str(path)) == 1
    captured = capsys.readouterr()
    assert "Render service configuration or startup failed" in captured.out
    assert TOKEN not in captured.out + captured.err and SECRET not in captured.out + captured.err

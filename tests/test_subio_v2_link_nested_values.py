import base64
import json
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.links import codecs as links
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.core.nodes import Network
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.rendering import prepare_resources
from subio_v2.workflow.parameters import normalize_parameters


def _node(protocol="vmess"):
    data = {
        "name": "node", "type": protocol, "server": "example.test", "port": 443,
        "tls": True,
    }
    if protocol in {"vmess", "vless", "tuic"}:
        data["uuid"] = "synthetic-uuid"
    if protocol not in {"vmess", "vless"}:
        data["password"] = "synthetic-password"
    if protocol == "tuic":
        data["version"] = 5
    if protocol == "ss":
        data.update(cipher="aes-256-gcm", plugin="obfs")
    result = get_parser("mihomo").parse_result(yaml.safe_dump({"proxies": [data]}))
    assert not result.issues
    return result.nodes[0]


def _payload(uri):
    if uri.startswith("vmess://"):
        return json.loads(base64.b64decode(uri.removeprefix("vmess://")))
    return {key: values[0] for key, values in parse_qs(urlsplit(uri).query).items()}


@pytest.mark.parametrize("protocol,target", [
    ("vmess", "v2rayn"), ("vless", "v2rayn"), ("trojan", "v2rayn"),
    ("anytls", "dae"), ("tuic", "dae"), ("hysteria2", "dae"),
])
@pytest.mark.parametrize("value", ["h2,http/1.1", "", ",h2", "h2,"])
def test_all_comma_alpn_builders_reject_ambiguous_elements(protocol, target, value):
    node = _node(protocol)
    node.tls.alpn = [value]
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and not result.content
    assert len(result.errors) == 1
    issue = result.errors[0]
    assert (issue.field, issue.code, issue.stage) == (
        "tls.alpn", "conversion.invalid-value", "emit"
    )


@pytest.mark.parametrize("protocol,target", [
    ("vmess", "v2rayn"), ("vless", "v2rayn"), ("trojan", "v2rayn"),
    ("anytls", "dae"), ("tuic", "dae"), ("hysteria2", "dae"),
])
def test_alpn_safe_elements_survive_outer_decode_and_inner_split(protocol, target):
    node = _node(protocol)
    node.tls.alpn = ["", " h2 ", "", "http/1.1", "%2C;equals=value&plus+", ""]
    result = get_emitter(target).emit_result([node])
    assert not result.errors
    uri = (
        base64.b64decode(result.content).decode()
        if target == "v2rayn" else result.fragments.subscription
    )
    assert _payload(uri)["alpn"].split(",") == node.tls.alpn


@pytest.mark.parametrize("values", [["", "h2"], ["h2", ""], ["h2", "", "http/1.1"], ["", ""]])
def test_vmess_alpn_empty_neighbors_roundtrip_through_actual_consumer(values):
    node = _node()
    node.tls.alpn = values
    decoded = links.parse_url(links.build_url(node))
    assert decoded is not None
    assert decoded.tls.alpn == values


@pytest.mark.parametrize("protocol", ["vmess", "vless", "trojan"])
@pytest.mark.parametrize("host", [["one.test,two.test"], [""], "one.test,two.test"])
def test_h2_host_builders_reject_ambiguous_list_and_scalar_values(protocol, host):
    node = _node(protocol)
    node.transport.network = Network.H2
    node.transport.host = host
    result = get_emitter("v2rayn").emit_result([node])
    assert not result.supported_nodes and not result.content
    assert len(result.errors) == 1
    assert result.errors[0].field == "transport.host"
    assert result.errors[0].code == "conversion.invalid-value"


@pytest.mark.parametrize("protocol", ["vmess", "vless", "trojan"])
def test_h2_host_safe_elements_roundtrip_without_trimming(protocol):
    node = _node(protocol)
    node.transport.network = Network.H2
    node.transport.host = ["", " one.test ", "", "two%2C.test;equals=value", ""]
    decoded = links.parse_url(links.build_url(node))
    assert decoded is not None
    assert decoded.transport.host == node.transport.host


@pytest.mark.parametrize("protocol", ["vmess", "vless"])
@pytest.mark.parametrize("path", [["/one,/two"], [""]])
def test_http_path_joins_reject_ambiguous_elements(protocol, path):
    node = _node(protocol)
    node.transport.network = Network.HTTP
    node.transport.path = path
    result = get_emitter("v2rayn").emit_result([node])
    assert not result.supported_nodes and not result.content
    assert len(result.errors) == 1
    assert result.errors[0].field == "transport.path"
    assert result.errors[0].code == "conversion.invalid-value"


def test_vless_http_scalar_path_cannot_be_reinterpreted_as_multiple_paths():
    node = _node("vless")
    node.transport.network = Network.HTTP
    node.transport.path = "/one,/two"
    assert get_emitter("v2rayn").emit_result([node]).errors[0].field == "transport.path"


@pytest.mark.parametrize("protocol", ["vmess", "vless"])
def test_http_path_safe_elements_survive_outer_decode_and_inner_split(protocol):
    node = _node(protocol)
    node.transport.network = Network.HTTP
    node.transport.path = ["", " /one ", "", "/two%2C;equals=value&plus+", ""]
    uri = links.build_url(node)
    assert _payload(uri)["path"].split(",") == node.transport.path
    if protocol == "vless":
        assert links.parse_url(uri).transport.path == node.transport.path


@pytest.mark.parametrize("value", ["good.test;injected=other", ";", "good.test;"])
@pytest.mark.parametrize("target", ["dae", "v2rayn"])
def test_ss_plugin_option_semicolons_are_structured_encoding_errors(value, target):
    node = _node("ss")
    node.plugin_opts = {"mode": "http", "host": value}
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and not result.content
    assert len(result.errors) == 1
    issue = result.errors[0]
    assert (issue.field, issue.code, issue.stage) == (
        "plugin_opts", "conversion.invalid-value", "emit"
    )
    assert value not in issue.message


def test_ss_plugin_name_and_static_option_keys_cannot_add_inner_structure():
    node = _node("ss")
    node.plugin = "obfs;injected=other"
    with pytest.raises(ValueError, match="Plugin name is not representable"):
        links.build_url(node)
    node.plugin = "obfs"
    for key in ("host;injected", "host=injected"):
        node.plugin_opts = {key: "value"}
        with pytest.raises(ValueError, match="Plugin option is not representable"):
            links.build_url(node)


def _fixture(tmp_path, family, case, *, empty_neighbors=False):
    native = family == "subio"
    node = {
        "name": "parameterized", "type": "vmess", "server": "example.test",
        "port": 443, "uuid": "synthetic-uuid",
    }
    value = "{{ params.value }}"
    values = [value, "h2" if case == "alpn" else "safe.test", value] if empty_neighbors else [value]
    if case == "alpn":
        if native:
            node["tls"] = {"enabled": True, "alpn": values}
        else:
            node.update(tls=True, alpn=values)
    elif case == "host":
        if native:
            node["transport"] = {"network": "h2", "host": values}
        else:
            node.update(network="h2", **{"h2-opts": {"host": values}})
    else:
        node.pop("uuid")
        node.update(
            type="shadowsocks" if native else "ss", cipher="aes-256-gcm",
            password="synthetic-password", plugin="obfs",
        )
        node["plugin_opts" if native else "plugin-opts"] = {"mode": "http", "host": value}
    safe = {
        "name": "safe", "type": "vmess", "server": "safe.test", "port": 443,
        "uuid": "synthetic-safe-uuid",
    }
    document = {"version": 2, "nodes": [node, safe]} if native else {"proxies": [node, safe]}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    data = {
        "allow_conversion_errors": True,
        "provider": [{"name": "source", "type": family, "file": "nodes.yaml", "parameterized": True}],
        "artifact": [{"name": "out.txt", "type": "v2rayn", "providers": ["source"],
                      "allow_conversion_errors": True,
                      "params": {
                          "value": {"type": "string"},
                      }}],
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return path, ConfigLoader.load(str(path))


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("case,value,field", [
    ("alpn", "h2,http/1.1", "tls.alpn"), ("alpn", "", "tls.alpn"),
    ("host", "one.test,two.test", "transport.host"), ("host", "", "transport.host"),
    ("plugin", "good.test;injected=other", "plugin_opts"),
])
def test_nested_link_errors_block_prepare_and_http_before_partial_staging(
    tmp_path, monkeypatch, family, case, value, field
):
    pytest.importorskip("starlette")
    from starlette.testclient import TestClient
    from subio_v2 import server

    path, config = _fixture(tmp_path, family, case)
    params = normalize_parameters(config.artifacts[0].params, [("value", value)])
    candidate = prepare_resources(str(path), config).candidates["out.txt"]
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged partial nested-link output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        candidate.render("out.txt", params)
    assert any(
        issue.field == field and issue.code == "conversion.invalid-value"
        and issue.severity == "error" and issue.stage == "emit"
        for issue in error.value.issues
    )
    token = "synthetic_nested_link_token_0123456789"
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", token)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.txt?" + urlencode({"token": token, "value": value}))
    assert response.status_code == 422
    assert response.json() == {"error": "conversion_rejected"}
    assert response.headers["cache-control"] == "no-store, private"
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("case", ["alpn", "host"])
def test_parameterized_empty_neighbors_roundtrip_through_prepare_and_http(
    tmp_path, monkeypatch, family, case
):
    pytest.importorskip("starlette")
    from starlette.testclient import TestClient
    from subio_v2 import server

    path, config = _fixture(tmp_path, family, case, empty_neighbors=True)
    params = normalize_parameters(config.artifacts[0].params, [("value", "")])
    prepared = prepare_resources(str(path), config).candidates["out.txt"].render("out.txt", params)
    token = "synthetic_nested_link_token_0123456789"
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", token)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.txt?" + urlencode({"token": token, "value": ""}))
    assert response.status_code == 200
    assert response.text == prepared.artifact_result.drafts[0].content
    result = get_parser("v2rayn").parse_result(response.text)
    assert not result.issues and len(result.nodes) == 2
    node = result.nodes[0]
    assert (node.tls.alpn if case == "alpn" else node.transport.host) == [
        "", "h2" if case == "alpn" else "safe.test", ""
    ]
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("case,value", [
    ("alpn", " h2 "), ("alpn", "h2%2Chttp/1.1"),
    ("host", " one.test "), ("host", "one%2C.test"),
    ("plugin", "good.test"), ("plugin", " a=b,c%3B&plus+ "), ("plugin", ""),
])
def test_nested_link_safe_neighbors_roundtrip_from_both_providers_over_http(
    tmp_path, monkeypatch, family, case, value
):
    pytest.importorskip("starlette")
    from starlette.testclient import TestClient
    from subio_v2 import server

    path, config = _fixture(tmp_path, family, case)
    params = normalize_parameters(config.artifacts[0].params, [("value", value)])
    prepared = prepare_resources(str(path), config).candidates["out.txt"].render("out.txt", params)
    content = prepared.artifact_result.drafts[0].content
    token = "synthetic_nested_link_token_0123456789"
    monkeypatch.setenv("SUBIO_RENDER_TOKEN", token)
    with TestClient(server.create_app(str(path))) as client:
        response = client.get("/subscription/out.txt?" + urlencode({"token": token, "value": value}))
    assert response.status_code == 200
    assert response.text == content
    result = get_parser("v2rayn").parse_result(response.text)
    assert not result.issues and len(result.nodes) == 2
    node = result.nodes[0]
    if case == "alpn":
        assert node.tls.alpn == [value]
    elif case == "host":
        assert node.transport.host == [value]
    else:
        assert node.plugin == "obfs"
        assert node.plugin_opts == {"mode": "http", "host": value}
    assert not (tmp_path / "dist").exists()

import json

import pytest
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.core.nodes import Protocol, TailscaleNode, WireguardNode
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.parameters import normalize_parameters

TOKEN = "synthetic_surge_boundary_0123456789"
SCALARS = [
    ("tailscale", (field,))
    for field in ("auth_key", "hostname", "control_url", "exit_node")
] + [
    ("wireguard", (field,))
    for field in ("private_key", "interface_ip", "interface_ipv6")
]
SOURCE_KEYS = {
    "auth_key": "auth-key", "control_url": "control-url", "exit_node": "exit-node",
    "private_key": "private-key", "public_key": "public-key",
    "preshared_key": "preshared-key", "interface_ip": "ip", "interface_ipv6": "ipv6",
    "allowed_ips": "allowed-ips", "dns_servers": "dns",
}


def _source_key(family, key):
    return SOURCE_KEYS.get(key, key) if family == "mihomo" else key


def _source_node(family, protocol, *, peers=False):
    node = {"name": "safe", "type": protocol}
    fields = {
        "socks5": {"server": "example.test", "port": 1080, "username": "user", "password": "password"},
        "tailscale": {"auth_key": "auth", "hostname": "client", "control_url": "https://control.test", "exit_node": "exit"},
        "wireguard": {
            "server": "example.test", "port": 51820, "private_key": "private",
            "public_key": "public", "preshared_key": "shared",
            "interface_ip": "10.0.0.2", "interface_ipv6": "fd00::2",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
        },
    }[protocol]
    node.update({_source_key(family, key): value for key, value in fields.items()})
    if peers:
        node["peers"] = [
            {_source_key(family, key): value for key, value in {
                "server": f"peer{index}.test", "port": 51820 + index,
                "public_key": f"public{index}", "preshared_key": f"shared{index}",
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            }.items()}
            for index in range(2)
        ]
    return node


def _fixture(tmp_path, family, protocol, field, *, value="{{ params.value }}", parameterized=True):
    node = _source_node(family, protocol, peers=field[0] == "peers")
    target = node
    for key in field[:-1]:
        source_key = _source_key(family, key)
        if isinstance(target, dict) and source_key not in target:
            target[source_key] = ["static", "neighbor"]
        target = target[source_key]
    if isinstance(target, list):
        target[:] = ["static", "neighbor"]
    target[_source_key(family, field[-1])] = value
    key = "nodes" if family == "subio" else "proxies"
    document = {key: [node, _source_node(family, "socks5")]}
    document[key][1]["name"] = "neighbor"
    if family == "subio":
        document["version"] = 2
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    (tmp_path / "client.j2").write_text("[Proxy]\n{{ nodes.render() }}")
    config = {
        "allow_conversion_errors": True,
        "provider": [{"name": "source", "type": family, "file": "nodes.yaml", "parameterized": parameterized}],
        "artifact": [{
            "name": "surge.conf", "type": "surge", "providers": ["source"],
            "template": "client.j2", "allow_conversion_errors": True,
            "render": {"route": "demo", "params": {"value": {"type": "string", "required": True, "allow_empty": True}}},
        }],
    }
    if not parameterized:
        config["artifact"][0].pop("render")
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def _prepare(path, value):
    config = ConfigLoader.load(str(path))
    values = normalize_parameters(config.artifacts[0].render.params, [("value", value)])
    engine = WorkflowEngine.for_render(str(path), config, "demo", values)
    assert not engine.config.allow_conversion_errors
    assert not engine.config.artifacts[0].allow_conversion_errors
    return engine.prepare()


def _http(path, value, monkeypatch):
    pytest.importorskip("starlette")
    pytest.importorskip("uvicorn")
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient

    from subio_v2.server import create_app

    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    with TestClient(create_app(str(path))) as client:
        response = client.get("/render/demo", params={"token": TOKEN, "value": value})
    assert response.headers["cache-control"] == "no-store, private"
    return response


def _read(node, field):
    value = node
    for key in field:
        value = value[key] if isinstance(key, int) else getattr(value, key)
    return value


def _round_trip(content, field, value):
    parsed = get_parser("surge").parse_result(content)
    assert parsed.issues == [] and len(parsed.nodes) == 2
    node = parsed.nodes[0]
    assert _read(node, field) == value
    if isinstance(field[-1], int):
        assert _read(node, field[:-1]) == [value, "neighbor"]


def _successful_request(tmp_path, monkeypatch, family, protocol, field, value):
    path = _fixture(tmp_path, family, protocol, field)
    prepared = _prepare(path, value).artifact_result
    assert not prepared.issues
    _round_trip(prepared.drafts[0].content, field, value)
    response = _http(path, value, monkeypatch)
    assert response.status_code == 200
    assert response.headers["content-disposition"] == "attachment"
    _round_trip(response.text, field, value)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("field", [("server",), ("username",), ("password",)])
@pytest.mark.parametrize("value", ["(", ")", "left(", "right)", "balanced(value)", "comma,value", 'say "hello"', " padded ", r"back\slash"])
def test_literal_atom_values_survive_prepare_and_real_http(tmp_path, monkeypatch, family, field, value):
    _successful_request(tmp_path, monkeypatch, family, "socks5", field, value)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("protocol", ["wireguard", "tailscale"])
@pytest.mark.parametrize("value", ["safe", "internal space", "balanced(name)"])
def test_generated_section_names_round_trip_with_safe_names(tmp_path, monkeypatch, family, protocol, value):
    _successful_request(tmp_path, monkeypatch, family, protocol, ("name",), value)


UNREPRESENTABLE = [
    (protocol, ("name",), value)
    for protocol in ("wireguard", "tailscale")
    for value in ("right]", "a[b]", "[whole]")
] + [
    (protocol, field, value)
    for protocol, field in SCALARS
    for value in (" leading", "trailing ", " both ")
] + [
    ("wireguard", field, value)
    for field in (("server",), ("peers", 0, "server"))
    for value in (" leading", " both ", "[2001:db8::1]")
]


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("protocol, field, value", UNREPRESENTABLE)
def test_unrepresentable_section_values_block_before_draft_and_http_success(
    tmp_path, monkeypatch, family, protocol, field, value
):
    path = _fixture(tmp_path, family, protocol, field)
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged an unrepresentable Surge value"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        _prepare(path, value)
    expected_field = ".".join(str(item) for item in field).replace("peers.0.", "peers[0].")
    assert any(
        issue.field == expected_field and issue.code == "conversion.invalid-value"
        and issue.severity == "error"
        for issue in error.value.issues
    )
    response = _http(path, value, monkeypatch)
    assert response.status_code == 422
    assert response.json() == {"error": "conversion_rejected"}
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("protocol, field", SCALARS)
@pytest.mark.parametrize("value", ["literal=value", '(balanced), "quoted" \\ interior'])
def test_raw_section_scalars_preserve_faithful_neighbors(tmp_path, monkeypatch, family, protocol, field, value):
    _successful_request(tmp_path, monkeypatch, family, protocol, field, value)


@pytest.mark.parametrize("family, protocol, field", [
    (family, "wireguard", field)
    for family in ("mihomo", "subio")
    for field in (("dns_servers", 0), ("allowed_ips", 0), ("peers", 0, "allowed_ips", 0))
] + [("subio", "tailscale", ("dns_servers", 0))])
@pytest.mark.parametrize("value", ["comma,value", " padded ", "left(", 'say "hello"', r"back\slash", ""])
def test_nested_csv_values_keep_one_element_and_exact_text(tmp_path, monkeypatch, family, protocol, field, value):
    _successful_request(tmp_path, monkeypatch, family, protocol, field, value)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("field, value", [
    (field, value)
    for field in (("preshared_key",), ("peers", 0, "preshared_key"), ("peers", 0, "public_key"), ("peers", 0, "server"))
    for value in ("literal=value", "comma,value", " padded ", "left(", 'say "hello"', r"back\slash")
    if field[-1] != "server" or value == value.strip()
])
def test_peer_atoms_and_flat_preshared_key_round_trip(tmp_path, monkeypatch, family, field, value):
    _successful_request(tmp_path, monkeypatch, family, "wireguard", field, value)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("field", [("server",), ("peers", 0, "server")])
@pytest.mark.parametrize("value", ["trailing ", "2001:db8::1", " 2001:db8::1 ", "a[b]"])
def test_wireguard_endpoint_neighbors_keep_the_original_server(tmp_path, monkeypatch, family, field, value):
    _successful_request(tmp_path, monkeypatch, family, "wireguard", field, value)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("protocol, field, value", [
    ("wireguard", ("name",), "right]"),
    ("tailscale", ("name",), "right]"),
    ("wireguard", ("private_key",), " private "),
    ("tailscale", ("auth_key",), " auth "),
    ("wireguard", ("server",), " host "),
])
def test_static_opt_out_still_allows_partial_draft(tmp_path, family, protocol, field, value):
    path = _fixture(tmp_path, family, protocol, field, value=value, parameterized=False)
    result = WorkflowEngine(str(path)).prepare().artifact_result
    assert result.drafts and any(issue.severity == "error" for issue in result.issues)


def test_bracketed_proxy_only_name_is_not_a_section_name():
    node = get_parser("mihomo").parse_result("proxies: [{name: '[Proxy]', type: socks5, server: example.test, port: 1080}]").nodes[0]
    emitted = get_emitter("surge").emit_result([node])
    assert emitted.issues == []
    assert get_parser("surge").parse_result("[Proxy]\n" + emitted.content).nodes[0].name == "[Proxy]"


@pytest.mark.parametrize("protocol, field", SCALARS)
def test_raw_section_line_breaks_fail_with_safe_field_issue(protocol, field):
    node = (
        TailscaleNode(name="tail", type=Protocol.TAILSCALE, auth_key="auth")
        if protocol == "tailscale" else WireguardNode(
            name="wg", type=Protocol.WIREGUARD, server="host", port=51820,
            private_key="private", public_key="public", interface_ip="10.0.0.2",
        )
    )
    setattr(node, field[0], "canary\nnew-section")
    emitted = get_emitter("surge").emit_result([node])
    assert not emitted.content and not emitted.supported_nodes
    assert any(issue.field == field[0] and issue.code == "conversion.invalid-value" for issue in emitted.errors)
    assert all("canary" not in issue.message for issue in emitted.issues)

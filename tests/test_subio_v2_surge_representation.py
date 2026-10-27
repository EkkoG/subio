import json

import pytest
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.nodes import Protocol, TailscaleNode, WireguardNode
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.parameters import normalize_parameters
from subio_v2.workflow.rendering import prepare_resources

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
    return _document_fixture(tmp_path, family, node, parameterized=parameterized)


def _document_fixture(tmp_path, family, node, *, parameterized=True):
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
            "params": {"value": {"type": "string"}},
        }],
    }
    if not parameterized:
        config["artifact"][0].pop("params")
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def _prepare(path, value):
    config = ConfigLoader.load(str(path))
    values = normalize_parameters(config.artifacts[0].params, [("value", value)])
    candidate = prepare_resources(str(path), config).candidates["surge.conf"]
    return candidate.render("surge.conf", values)


def _http(path, value, monkeypatch):
    pytest.importorskip("starlette")
    pytest.importorskip("uvicorn")
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient

    from subio_v2.server import create_app

    monkeypatch.setenv("SUBIO_RENDER_TOKEN", TOKEN)
    with TestClient(create_app(str(path))) as client:
        response = client.get("/subscription/surge.conf", params={"token": TOKEN, "value": value})
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


def _assert_only_neighbor(content):
    parsed = get_parser("surge").parse_result(content)
    assert not parsed.issues and len(parsed.nodes) == 1
    node = parsed.nodes[0]
    assert (node.name, node.type, node.server, node.port, node.username, node.password) == (
        "neighbor", Protocol.SOCKS5, "example.test", 1080, "user", "password"
    )
    assert content == "[Proxy]\n" + get_emitter("surge").emit_result(parsed.nodes).content


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
def test_unrepresentable_section_values_skip_node_in_prepare_and_http(
    tmp_path, monkeypatch, family, protocol, field, value
):
    path = _fixture(tmp_path, family, protocol, field)
    result = _prepare(path, value).artifact_result
    expected_field = ".".join(str(item) for item in field).replace("peers.0.", "peers[0].")
    assert any(
        issue.field == expected_field and issue.code == "conversion.invalid-value"
        and issue.severity == "error"
        for issue in result.issues
    )
    _assert_only_neighbor(result.drafts[0].content)
    response = _http(path, value, monkeypatch)
    assert response.status_code == 200
    assert response.text == result.drafts[0].content
    _assert_only_neighbor(response.text)
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


def _nested_node(family, protocol):
    node = {"name": "safe", "type": protocol, "server": "example.test", "port": 443}
    if protocol in {"vmess", "tuic"}:
        node["uuid"] = "synthetic-uuid"
    if protocol not in {"vmess", "socks5", "http", "masque"}:
        node["password"] = "synthetic-password"
    if protocol in {"ssh", "trusttunnel"}:
        node["username"] = "synthetic-user"
    if protocol in {"http", "trusttunnel"}:
        node["udp"] = False
    if protocol == "tuic" and family == "subio":
        node["version"] = 5
    if family == "subio":
        if protocol != "ssh":
            node["tls"] = {"enabled": True}
    elif protocol in {"vmess", "trojan", "socks5", "http"}:
        node["tls"] = True
    return node


def _nested_success(path, value, field, expected, monkeypatch):
    prepared = _prepare(path, value).artifact_result
    assert not prepared.issues
    _round_trip(prepared.drafts[0].content, field, expected)
    response = _http(path, value, monkeypatch)
    assert response.status_code == 200
    assert response.headers["content-disposition"] == "attachment"
    _round_trip(response.text, field, expected)


def _nested_rejection(path, value, field, monkeypatch):
    result = _prepare(path, value).artifact_result
    assert any(
        (issue.field, issue.code, issue.severity, issue.stage)
        == (field, "conversion.invalid-value", "error", "emit")
        for issue in result.issues
    )
    _assert_only_neighbor(result.drafts[0].content)
    response = _http(path, value, monkeypatch)
    assert response.status_code == 200
    assert response.text == result.drafts[0].content
    _assert_only_neighbor(response.text)
    assert not (path.parent / "dist").exists()


HEADER_PLACEMENTS = [
    (family, protocol, None, True)
    for family in ("mihomo", "subio") for protocol in ("vmess", "trojan")
] + [
    (family, "http", variant, enabled)
    for family in ("mihomo", "subio")
    for variant in (("auto",) if family == "mihomo" else ("auto", "http", "https", "h2-connect"))
    for enabled in ((False, True) if variant == "auto" else (variant != "http",))
]


@pytest.mark.parametrize("family, protocol, variant, enabled", HEADER_PLACEMENTS)
@pytest.mark.parametrize("value", [
    "safe|Injected:changed", "safe;Injected:changed", " padded ", "",
    "safe;equal=value%2C+", "safe|equal=value%2C+",
    'comma,quotes"(value)=equal%2C+\\backslash',
])
def test_header_inner_values_are_faithful_or_skip_node(
    tmp_path, monkeypatch, family, protocol, variant, enabled, value
):
    node = _nested_node(family, protocol)
    headers = {"X-Review": "{{ params.value }}", "X-Static": "neighbor"}
    if protocol == "http":
        node["headers"] = headers
        node["tls"] = {"enabled": enabled} if family == "subio" else enabled
        if family == "subio":
            node["variant"] = variant
        separator, field, issue_field = ";", ("headers",), "headers"
    else:
        if family == "subio":
            node["transport"] = {"network": "ws", "headers": headers}
        else:
            node.update(network="ws", **{"ws-opts": {"headers": headers}})
        separator, field, issue_field = "|", ("transport", "headers"), "transport.headers"
    path = _document_fixture(tmp_path, family, node)
    if separator in value or value != value.strip():
        _nested_rejection(path, value, issue_field, monkeypatch)
    else:
        _nested_success(path, value, field, {"X-Review": value, "X-Static": "neighbor"}, monkeypatch)


@pytest.mark.parametrize("family, protocol", [
    (family, protocol) for family in ("mihomo", "subio") for protocol in ("vmess", "trojan", "http")
])
@pytest.mark.parametrize("key", [" padded ", "Colon:Key", "Inner|Key", "Inner;Key", ""])
def test_header_keys_obey_only_the_selected_inner_grammar(tmp_path, monkeypatch, family, protocol, key):
    node = _nested_node(family, protocol)
    headers = {key: "{{ params.value }}", "X-Static": "neighbor"}
    if protocol == "http":
        node["headers"] = headers
        separator, field, issue_field = ";", ("headers",), "headers"
    else:
        if family == "subio":
            node["transport"] = {"network": "ws", "headers": headers}
        else:
            node.update(network="ws", **{"ws-opts": {"headers": headers}})
        separator, field, issue_field = "|", ("transport", "headers"), "transport.headers"
    path = _document_fixture(tmp_path, family, node)
    if separator in key or ":" in key or key != key.strip():
        _nested_rejection(path, "safe", issue_field, monkeypatch)
    else:
        _nested_success(path, "safe", field, {key: "safe", "X-Static": "neighbor"}, monkeypatch)


TLS_PLACEMENTS = [
    (family, protocol)
    for family in ("mihomo", "subio")
    for protocol in ("vmess", "trojan", "socks5", "http", "anytls", "tuic", "hysteria2", "trusttunnel")
] + [("subio", "masque")]


@pytest.mark.parametrize("family, protocol", TLS_PLACEMENTS)
@pytest.mark.parametrize("shape", ["single", "first", "last", "both", "sandwich"])
@pytest.mark.parametrize("value", ["h2,http/1.1", " h2 ", "", "h2", "%2C;equal=value+"])
def test_shared_alpn_preserves_exact_elements_or_skips_node(
    tmp_path, monkeypatch, family, protocol, shape, value
):
    node = _nested_node(family, protocol)
    token = "{{ params.value }}"
    values = {
        "single": [token], "first": [token, "h3"], "last": ["h3", token],
        "both": [token, token], "sandwich": [token, "h3", token],
    }[shape]
    if family == "subio":
        node["tls"]["alpn"] = values
    else:
        node["alpn"] = values
    path = _document_fixture(tmp_path, family, node)
    expected = [value if item == token else item for item in values]
    strips = len(expected) > 1 or protocol in {"masque", "trusttunnel"}
    if "," in value or expected == [""] or (strips and value != value.strip()):
        _nested_rejection(path, value, "tls.alpn", monkeypatch)
    else:
        _nested_success(path, value, ("tls", "alpn"), expected, monkeypatch)


@pytest.mark.parametrize("family, protocol", TLS_PLACEMENTS)
@pytest.mark.parametrize("value", ["off", "OFF", " off ", "safe.example"])
def test_literal_sni_off_cannot_become_the_disable_instruction(
    tmp_path, monkeypatch, family, protocol, value
):
    node = _nested_node(family, protocol)
    if family == "subio":
        node["tls"]["server_name"] = "{{ params.value }}"
    else:
        node["sni"] = "{{ params.value }}"
    path = _document_fixture(tmp_path, family, node)
    if value == "off":
        _nested_rejection(path, value, "tls.server_name", monkeypatch)
    else:
        _nested_success(path, value, ("tls", "server_name"), value, monkeypatch)


@pytest.mark.parametrize("protocol", [protocol for family, protocol in TLS_PLACEMENTS if family == "subio"])
def test_explicit_sni_disable_remains_supported(tmp_path, monkeypatch, protocol):
    node = _nested_node("subio", protocol)
    node["tls"].update(sni_disabled=True, server_name="{{ params.value }}")
    path = _document_fixture(tmp_path, "subio", node)
    _nested_success(path, "off", ("tls", "sni_disabled"), True, monkeypatch)
    _nested_success(path, "off", ("tls", "server_name"), None, monkeypatch)


@pytest.mark.parametrize("value", ["one,two", "", " padded ", "%2C;equal=value+", 'say "hello"(fingerprint)'])
def test_native_ssh_fingerprint_elements_are_faithful_or_skip_node(tmp_path, monkeypatch, value):
    node = _nested_node("subio", "ssh")
    node["server_fingerprints"] = ["{{ params.value }}", "neighbor"]
    path = _document_fixture(tmp_path, "subio", node)
    if not value or "," in value:
        _nested_rejection(path, value, "server_fingerprints", monkeypatch)
    else:
        _nested_success(path, value, ("server_fingerprints",), [value, "neighbor"], monkeypatch)


@pytest.mark.parametrize("case", ["headers", "alpn", "sni", "fingerprints"])
def test_static_opt_out_still_allows_partial_output_for_inner_grammar_errors(tmp_path, case):
    node = _nested_node("subio", "ssh" if case == "fingerprints" else "trojan")
    if case == "headers":
        node["transport"] = {"network": "ws", "headers": {"Host": "safe|Injected:changed"}}
    elif case == "alpn":
        node["tls"]["alpn"] = ["h2,http/1.1", "h3"]
    elif case == "sni":
        node["tls"]["server_name"] = "off"
    else:
        node["server_fingerprints"] = ["one,two", "neighbor"]
    path = _document_fixture(tmp_path, "subio", node, parameterized=False)
    result = WorkflowEngine(str(path)).prepare().artifact_result
    assert len(result.drafts) == 1
    assert any(issue.severity == "error" and issue.code == "conversion.invalid-value" for issue in result.issues)
    parsed = get_parser("surge").parse_result(result.drafts[0].content)
    assert not parsed.issues and [node.name for node in parsed.nodes] == ["neighbor"]


@pytest.mark.parametrize("peers", [False, True])
@pytest.mark.parametrize("value", ["1/2", "/", "1/", "/2", "1/2/3"])
def test_mihomo_wireguard_client_id_elements_cannot_grow_the_inner_list(tmp_path, monkeypatch, peers, value):
    node = _source_node("mihomo", "wireguard", peers=peers)
    target = node["peers"][0] if peers else node
    target["reserved"] = ["{{ params.value }}", 2, 3]
    path = _document_fixture(tmp_path, "mihomo", node)
    _nested_rejection(path, value, "peers[0].reserved" if peers else "reserved", monkeypatch)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("peers", [False, True])
@pytest.mark.parametrize("value", [0, 1, 255])
def test_wireguard_integer_client_id_neighbors_remain_exact(tmp_path, monkeypatch, family, peers, value):
    node = _source_node(family, "wireguard", peers=peers)
    target = node["peers"][0] if peers else node
    target["reserved"] = ["{{ params.value }}", 2, 3]
    path = _document_fixture(tmp_path, family, node)
    config = json.loads(path.read_text())
    config["artifact"][0]["params"]["value"] = {"type": "integer"}
    path.write_text(json.dumps(config))
    field = ("peers", 0, "reserved") if peers else ("reserved",)
    _nested_success(path, str(value), field, [value, 2, 3], monkeypatch)


@pytest.mark.parametrize("value", ["1", " 1 ", -1, 256])
def test_client_id_guard_does_not_add_numeric_or_byte_validation(value):
    node = get_parser("mihomo").parse_result(yaml.safe_dump({
        "proxies": [_source_node("mihomo", "wireguard")],
    })).nodes[0]
    node.reserved = [value, 2, 3]
    emitted = get_emitter("surge").emit_result([node])
    assert not emitted.issues
    parsed = get_parser("surge").parse_result("[Proxy]\n" + emitted.content)
    assert not parsed.issues
    peer = parsed.nodes[0].source_extensions["surge"]["wireguard"]["peers"][0]
    assert peer["client-id"] == f"{value}/2/3"


def _section_like_proxy(family, name, case, value):
    protocol = "http" if case == "headers" else ("anytls" if case == "anytls-password" else "socks5")
    node = _nested_node(family, protocol)
    node.update(name=name, udp=False)
    if case in {"password", "anytls-password"}:
        node["password"] = value
        field = ("password",)
    elif case == "interface":
        node["interface_name" if family == "subio" else "interface-name"] = value
        field = ("interface_name",)
    elif case == "sni":
        if family == "subio":
            node["tls"]["server_name"] = value
        else:
            node["sni"] = value
        field = ("tls", "server_name")
    else:
        node["headers"] = {"X-Review": value}
        field = ("headers",)
    return node, field


def _assert_proxy_and_following_neighbor(content, name, field, value):
    parsed = get_parser("surge").parse_result(content)
    assert not parsed.issues
    assert [node.name for node in parsed.nodes] == [name, "neighbor"]
    assert _read(parsed.nodes[0], field) == value
    assert parsed.nodes[1].server == "example.test"
    assert parsed.nodes[1].password == "password"


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("name", ["plain", "[literal]", "[open"])
@pytest.mark.parametrize("case", ["password", "interface", "sni", "headers", "anytls-password"])
@pytest.mark.parametrize("value", ["pw]", "safe", "pw]x", "pw],", 'quoted"pw]'])
def test_complete_proxy_line_preserves_both_nodes_through_prepare_and_http(
    tmp_path, monkeypatch, family, name, case, value
):
    node, field = _section_like_proxy(family, name, case, "{{ params.value }}")
    path = _document_fixture(tmp_path, family, node)
    result = _prepare(path, value).artifact_result
    assert not result.issues
    expected = {"X-Review": value} if case == "headers" else value
    _assert_proxy_and_following_neighbor(result.drafts[0].content, name, field, expected)
    response = _http(path, value, monkeypatch)
    assert response.status_code == 200
    assert response.headers["content-disposition"] == "attachment"
    _assert_proxy_and_following_neighbor(response.text, name, field, expected)
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("name", ["[literal]", "[open"])
@pytest.mark.parametrize("case", ["password", "interface", "sni", "headers", "anytls-password"])
def test_static_opt_out_keeps_both_nodes_for_section_like_proxy_lines(tmp_path, family, name, case):
    node, field = _section_like_proxy(family, name, case, "pw]")
    path = _document_fixture(tmp_path, family, node, parameterized=False)
    result = WorkflowEngine(str(path)).prepare().artifact_result
    assert not result.issues
    expected = {"X-Review": "pw]"} if case == "headers" else "pw]"
    _assert_proxy_and_following_neighbor(result.drafts[0].content, name, field, expected)


@pytest.mark.parametrize("family", ["mihomo", "subio"])
@pytest.mark.parametrize("name", ["[literal]", "[open"])
def test_parameterized_bracketed_name_with_static_closing_atom_remains_a_proxy(tmp_path, monkeypatch, family, name):
    node, field = _section_like_proxy(family, "{{ params.value }}", "password", "pw]")
    path = _document_fixture(tmp_path, family, node)
    prepared = _prepare(path, name).artifact_result
    assert not prepared.issues
    _assert_proxy_and_following_neighbor(prepared.drafts[0].content, name, field, "pw]")
    response = _http(path, name, monkeypatch)
    assert response.status_code == 200
    _assert_proxy_and_following_neighbor(response.text, name, field, "pw]")

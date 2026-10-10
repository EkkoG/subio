import pytest

from subio_v2.adapters.singbox.endpoint import (
    SINGBOX_ENDPOINT_CODECS,
    SINGBOX_ENDPOINT_CODECS_BY_TYPE,
    encode_endpoint,
)
from subio_v2.adapters.singbox.outbound import encode_outbound
from subio_v2.adapters.singbox.parser import SingBoxParser
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import (
    DirectNode,
    Protocol,
    TailscaleNode,
    WireguardNode,
    WireguardPeer,
)
from subio_v2.core.results import IssueSeverity


def _wireguard() -> dict:
    return {
        "type": "wireguard",
        "tag": "wg",
        "detour": "direct",
        "bind_interface": "en0",
        "routing_mark": 7,
        "tcp_multi_path": True,
        "address": ["10.0.0.2/32", "fd00::2/128"],
        "private_key": "private-secret",
        "mtu": 1420,
        "workers": 2,
        "peers": [
            {
                "address": "wg.example",
                "port": 51820,
                "public_key": "public-key",
                "pre_shared_key": "peer-secret",
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "reserved": [1, 2, 3],
            }
        ],
    }


def _tailscale() -> dict:
    return {
        "type": "tailscale",
        "tag": "ts",
        "detour": "direct",
        "bind_interface": "en1",
        "routing_mark": 8,
        "tcp_fast_open": True,
        "auth_key": "ts-secret",
        "control_url": "https://controlplane.tailscale.com",
        "ephemeral": True,
        "hostname": "subio",
        "accept_routes": True,
        "exit_node": "100.64.0.1",
        "exit_node_allow_lan_access": True,
    }


def _wireguard_node() -> WireguardNode:
    return WireguardNode(
        name="wg",
        private_key="private-secret",
        peers=[
            WireguardPeer(
                "wg.example",
                51820,
                "public-key",
                ["0.0.0.0/0"],
                preshared_key="peer-secret",
            )
        ],
    )


def _tailscale_node() -> TailscaleNode:
    return TailscaleNode(name="ts", udp=False, auth_key="ts-secret")


def test_singbox_endpoint_registry_is_explicit_and_structural():
    assert set(SINGBOX_ENDPOINT_CODECS_BY_TYPE) == {
        "openconnect",
        "openvpn-client",
        "tailscale",
        "wireguard",
    }
    assert set(SINGBOX_ENDPOINT_CODECS) == {
        Protocol.OPENCONNECT,
        Protocol.OPENVPN,
        Protocol.TAILSCALE,
        Protocol.WIREGUARD,
    }


def test_singbox_mixed_outbounds_and_endpoints_round_trip():
    parser = SingBoxParser()
    parsed = parser.parse_result(
        {
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "endpoints": [_wireguard(), _tailscale()],
        }
    )

    assert parsed.issues == []
    assert [node.type for node in parsed.nodes] == [
        Protocol.DIRECT,
        Protocol.WIREGUARD,
        Protocol.TAILSCALE,
    ]
    wireguard = parsed.nodes[1]
    tailscale = parsed.nodes[2]
    assert wireguard.server is None
    assert wireguard.port is None
    assert wireguard.public_key == ""
    assert wireguard.interface_name == "en0"
    assert tailscale.interface_name == "en1"

    encoded = {
        "outbounds": [encode_outbound(parsed.nodes[0])],
        "endpoints": [encode_endpoint(wireguard), encode_endpoint(tailscale)],
    }
    reparsed = parser.parse_result(encoded)
    assert reparsed.issues == []
    assert reparsed.nodes == parsed.nodes


def test_singbox_endpoint_only_document_is_supported():
    result = SingBoxParser().parse_result({"endpoints": [_wireguard()]})

    assert result.issues == []
    assert len(result.nodes) == 1
    assert isinstance(result.nodes[0], WireguardNode)


def test_singbox_endpoint_parser_errors_are_section_aware():
    result = SingBoxParser().parse_result({"endpoints": [None]})

    assert result.nodes == []
    assert result.issues[0].message == "Sing-box endpoint entry must be an object"


@pytest.mark.parametrize("endpoint_type", ["openvpn-server", "masque"])
def test_singbox_unimplemented_endpoint_types_fail_closed(endpoint_type):
    result = SingBoxParser().parse_result(
        {"endpoints": [{"type": endpoint_type, "tag": "unsupported"}]}
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.singbox.unsupported-type"
    assert result.issues[0].field == "endpoints[0].type"


@pytest.mark.parametrize(
    ("document", "field"),
    [
        ({"outbounds": [_wireguard()]}, "outbounds[0].type"),
        ({"endpoints": [{"type": "direct", "tag": "direct"}]}, "endpoints[0].type"),
    ],
)
def test_singbox_types_in_the_wrong_section_are_rejected(document, field):
    result = SingBoxParser().parse_result(document)

    assert result.nodes == []
    assert result.issues[0].code == "parse.singbox.unsupported-type"
    assert result.issues[0].field == field


@pytest.mark.parametrize(
    ("endpoint", "field"),
    [
        ({**_tailscale(), "state_directory": "/tmp/DO-NOT-READ"}, "state_directory"),
        ({**_tailscale(), "state_dir": "/tmp/DO-NOT-READ"}, "state_dir"),
        (
            {**_tailscale(), "taildrop_directory": "/tmp/DO-NOT-READ"},
            "taildrop_directory",
        ),
        ({**_tailscale(), "interactive_login": True}, "interactive_login"),
        ({**_tailscale(), "ssh_server": True}, "ssh_server"),
        ({**_wireguard(), "protect_path": "/tmp/DO-NOT-READ"}, "protect_path"),
        ({**_wireguard(), "netns": "runtime-service"}, "netns"),
    ],
)
def test_singbox_endpoint_paths_and_runtime_services_fail_closed(endpoint, field):
    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"
    assert "DO-NOT-READ" not in repr(result.issues)
    assert "private-secret" not in repr(result.issues)
    assert "ts-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("mutator", "field"),
    [
        (lambda endpoint: endpoint.update(name="wg0"), "name"),
        (lambda endpoint: endpoint.update(system=True), "system"),
        (lambda endpoint: endpoint.update(listen_port=51820), "listen_port"),
    ],
)
def test_singbox_wireguard_does_not_conflate_endpoint_interface_fields(mutator, field):
    endpoint = _wireguard()
    mutator(endpoint)

    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"


def test_singbox_wireguard_never_infers_a_peer_from_top_level_fields():
    node = WireguardNode(
        name="legacy-single-peer",
        server="wg.example",
        port=51820,
        private_key="private-secret",
        public_key="public-key",
    )

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert {issue.field for issue in result.issues} >= {
        "peers",
        "server",
        "port",
        "public_key",
    }
    assert "private-secret" not in repr(result.issues)


def test_singbox_endpoint_target_rejects_unrepresentable_existing_fields():
    wireguard = WireguardNode(
        name="wg",
        private_key="private-secret",
        peers=[WireguardPeer("wg.example", 51820, "public-key", ["0.0.0.0/0"])],
        persistent_keepalive=30,
    )
    tailscale = TailscaleNode(
        name="ts",
        udp=False,
        auth_key="ts-secret",
        state_dir="/tmp/DO-NOT-READ",
        interactive_login=True,
    )

    wg_result = TargetValidationService("sing-box").encode_node(
        wireguard, encode_endpoint
    )
    ts_result = TargetValidationService("sing-box").encode_node(
        tailscale, encode_endpoint
    )

    assert any(issue.field == "persistent_keepalive" for issue in wg_result.issues)
    assert {issue.field for issue in ts_result.issues} >= {
        "state_dir",
        "interactive_login",
    }
    assert "DO-NOT-READ" not in repr(ts_result.issues)
    assert "ts-secret" not in repr(ts_result.issues)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", 123),
        ("udp", "false"),
        ("tfo", "false"),
        ("mptcp", "false"),
        ("dialer_proxy", 7),
        ("interface_name", 7),
        ("routing_mark", True),
    ],
)
@pytest.mark.parametrize("factory", [_wireguard_node, _tailscale_node])
def test_singbox_endpoint_target_rejects_wrong_common_field_types(
    factory, field, value
):
    node = factory()
    setattr(node, field, value)

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == field
        for issue in result.issues
    )
    assert "private-secret" not in repr(result.issues)
    assert "peer-secret" not in repr(result.issues)
    assert "ts-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("mutator", "field"),
    [
        (lambda node: setattr(node, "private_key", ["private-secret"]), "private_key"),
        (
            lambda node: setattr(node.peers[0], "preshared_key", 7),
            "peers[0].preshared_key",
        ),
    ],
)
def test_singbox_wireguard_target_rejects_wrong_secret_field_types(mutator, field):
    node = _wireguard_node()
    mutator(node)

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == field
        for issue in result.issues
    )
    assert "private-secret" not in repr(result.issues)
    assert "peer-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_key", ["ts-secret"]),
        ("control_url", 7),
        ("hostname", 7),
        ("exit_node", []),
        ("ephemeral", "false"),
        ("accept_routes", 1),
        ("exit_node_allow_lan_access", None),
    ],
)
def test_singbox_tailscale_target_rejects_wrong_protocol_field_types(field, value):
    node = _tailscale_node()
    setattr(node, field, value)

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == field
        for issue in result.issues
    )
    assert "ts-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("peers", "field"),
    [
        ([{}], "peers[0]"),
        ([None], "peers[0]"),
        ("x", "peers"),
    ],
)
def test_singbox_wireguard_target_safely_rejects_malformed_peer_shapes(peers, field):
    node = _wireguard_node()
    node.peers = peers

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == field
        for issue in result.issues
    )
    assert "private-secret" not in repr(result.issues)


def test_singbox_endpoint_target_validates_constructed_peer_values():
    invalid_port = WireguardNode(
        name="wg",
        private_key="private-secret",
        peers=[
            WireguardPeer(
                "wg.example",
                70_000,
                "public-key",
                ["0.0.0.0/0"],
            )
        ],
    )
    invalid_reserved = WireguardNode(
        name="wg",
        private_key="private-secret",
        peers=[
            WireguardPeer(
                "wg.example",
                51820,
                "public-key",
                ["0.0.0.0/0"],
                reserved=[256],
            )
        ],
    )

    port_result = TargetValidationService("sing-box").encode_node(
        invalid_port, encode_endpoint
    )
    reserved_result = TargetValidationService("sing-box").encode_node(
        invalid_reserved, encode_endpoint
    )

    assert port_result.content is None
    assert reserved_result.content is None
    assert any(issue.field == "peers[0].port" for issue in port_result.issues)
    assert any(issue.field == "peers[0].reserved" for issue in reserved_result.issues)
    assert "private-secret" not in repr(port_result.issues)
    assert "private-secret" not in repr(reserved_result.issues)


@pytest.mark.parametrize(
    ("peer_field", "value"),
    [
        ("address", 7),
        ("port", "51820"),
        ("public_key", 7),
        ("allowed_ips", [7]),
        ("pre_shared_key", 7),
    ],
)
def test_singbox_wireguard_peer_helper_errors_keep_the_nested_path(peer_field, value):
    endpoint = _wireguard()
    endpoint["peers"][0][peer_field] = value

    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].peers[0].{peer_field}"
    assert "private-secret" not in repr(result.issues)
    assert "peer-secret" not in repr(result.issues)


@pytest.mark.parametrize("exit_node", ["auto", "auto:any", "none"])
def test_singbox_tailscale_rejects_platform_exit_node_selectors(exit_node):
    endpoint = {**_tailscale(), "exit_node": exit_node}
    parsed = SingBoxParser().parse_result({"endpoints": [endpoint]})
    node = _tailscale_node()
    node.exit_node = exit_node
    encoded = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert parsed.nodes == []
    assert parsed.issues[0].field == "endpoints[0].exit_node"
    assert parsed.issues[0].code == "parse.singbox.unsupported-protocol-variant"
    assert encoded.content is None
    assert encoded.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == "exit_node"
        for issue in encoded.issues
    )
    assert "ts-secret" not in repr(encoded.issues)


@pytest.mark.parametrize(
    ("endpoint", "field"),
    [
        ({**_wireguard(), "routing_mark": -1}, "routing_mark"),
        ({**_wireguard(), "mtu": 4_294_967_296}, "mtu"),
        (
            {**_wireguard(), "peers": [{**_wireguard()["peers"][0], "port": 0}]},
            "peers[0].port",
        ),
        (
            {
                **_wireguard(),
                "peers": [{**_wireguard()["peers"][0], "reserved": [256]}],
            },
            "peers[0].reserved",
        ),
        (
            {
                **_wireguard(),
                "peers": [
                    {**_wireguard()["peers"][0], "persistent_keepalive_interval": 30}
                ],
            },
            "peers[0].persistent_keepalive_interval",
        ),
    ],
)
def test_singbox_endpoint_official_ranges_are_validated(endpoint, field):
    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"


def test_singbox_endpoint_credentials_are_hidden_from_repr():
    wireguard = SingBoxParser().parse_result({"endpoints": [_wireguard()]}).nodes[0]
    tailscale = SingBoxParser().parse_result({"endpoints": [_tailscale()]}).nodes[0]

    assert "private-secret" not in repr(wireguard)
    assert "peer-secret" not in repr(wireguard)
    assert "ts-secret" not in repr(tailscale)
    assert "state-secret" not in repr(
        TailscaleNode(name="ts", auth_key="ts-secret", state_dir="state-secret")
    )
    assert "top-level-secret" not in repr(
        WireguardNode(name="wg", preshared_key="top-level-secret")
    )


def test_singbox_endpoint_target_support_is_codec_derived():
    service = TargetValidationService("sing-box")

    assert (
        service.protocol_codecs[Protocol.WIREGUARD]
        is SINGBOX_ENDPOINT_CODECS[Protocol.WIREGUARD]
    )
    assert (
        service.protocol_codecs[Protocol.TAILSCALE]
        is SINGBOX_ENDPOINT_CODECS[Protocol.TAILSCALE]
    )
    assert Protocol.DIRECT in service.protocol_codecs


def test_singbox_peer_wireguard_maps_to_mihomo_without_top_level_endpoint():
    parsed = SingBoxParser().parse_result({"endpoints": [_wireguard()]})
    assert parsed.issues == []
    node = parsed.nodes[0]
    service = TargetValidationService("mihomo")

    result = service.encode_node(node, service.protocol_codecs[node.type].emit)

    assert result.supported_node is node
    assert result.issues == []
    assert "server" not in result.content
    assert "port" not in result.content
    assert result.content["peers"] == [
        {
            "server": "wg.example",
            "port": 51820,
            "public-key": "public-key",
            "pre-shared-key": "peer-secret",
            "allowed-ips": ["0.0.0.0/0", "::/0"],
            "reserved": [1, 2, 3],
        }
    ]
    assert "private-secret" not in repr(result.issues)
    assert "peer-secret" not in repr(result.issues)


def test_singbox_peer_wireguard_is_rejected_by_stash_target_validation():
    parsed = SingBoxParser().parse_result({"endpoints": [_wireguard()]})
    assert parsed.issues == []
    node = parsed.nodes[0]
    service = TargetValidationService("stash")

    result = service.encode_node(node, service.protocol_codecs[node.type].emit)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == "peers"
        for issue in result.issues
    )
    assert "private-secret" not in repr(result.issues)
    assert "peer-secret" not in repr(result.issues)


@pytest.mark.parametrize("target", ["mihomo", "stash"])
def test_legacy_endpoint_wireguard_remains_supported_by_clash_targets(target):
    node = WireguardNode(
        name="legacy-wg",
        server="wg.example",
        port=51820,
        private_key="private-secret",
        public_key="public-key",
    )
    service = TargetValidationService(target)

    result = service.encode_node(node, service.protocol_codecs[node.type].emit)

    assert result.supported_node is node
    assert result.issues == []
    assert result.content["server"] == "wg.example"
    assert result.content["port"] == 51820
    assert "peers" not in result.content
    assert "private-secret" not in repr(result.issues)


def test_existing_outbound_parser_behavior_is_preserved():
    result = SingBoxParser().parse_result(
        {"outbounds": [{"type": "direct", "tag": "direct"}]}
    )

    assert result.issues == []
    assert result.nodes == [DirectNode(name="direct")]

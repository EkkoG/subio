import base64
import json
import urllib.parse
from collections.abc import Callable

import pytest

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.links import codecs as link
from subio_v2.adapters.target import TargetValidationService as NodeConversionService
from subio_v2.core.nodes import (
    AnyTLSNode,
    HttpNode,
    Hysteria2Node,
    Network,
    Node,
    Protocol,
    ShadowsocksNode,
    ShadowTLSSettings,
    Socks5Node,
    SurgePolicyOptions,
    TLSSettings,
    TransportSettings,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
)
from tests.support_target_views import all_platform_capabilities

PLATFORM_CAPABILITIES = all_platform_capabilities()


LINK_PLATFORMS = ("dae", "v2rayn")
TRANSPORT_PROTOCOLS = (Protocol.VMESS, Protocol.VLESS, Protocol.TROJAN)


def _base_node_factories() -> dict[Protocol, Callable[[], Node]]:
    return {
        Protocol.SHADOWSOCKS: lambda: ShadowsocksNode(
            name="ss",
            type=Protocol.SHADOWSOCKS,
            server="example.com",
            port=8388,
            cipher="aes-256-gcm",
            password="p",
        ),
        Protocol.VMESS: lambda: VmessNode(
            name="vmess",
            type=Protocol.VMESS,
            server="example.com",
            port=443,
            uuid="u",
        ),
        Protocol.VLESS: lambda: VlessNode(
            name="vless",
            type=Protocol.VLESS,
            server="example.com",
            port=443,
            uuid="u",
        ),
        Protocol.TROJAN: lambda: TrojanNode(
            name="trojan",
            type=Protocol.TROJAN,
            server="example.com",
            port=443,
            password="p",
        ),
        Protocol.SOCKS5: lambda: Socks5Node(
            name="socks5",
            type=Protocol.SOCKS5,
            server="example.com",
            port=1080,
        ),
        Protocol.HTTP: lambda: HttpNode(
            name="http",
            type=Protocol.HTTP,
            server="example.com",
            port=8080,
        ),
        Protocol.HYSTERIA2: lambda: Hysteria2Node(
            name="hysteria2",
            type=Protocol.HYSTERIA2,
            server="example.com",
            port=443,
            password="p",
            tls=TLSSettings(enabled=True),
        ),
        Protocol.TUIC: lambda: TUICNode(
            name="tuic",
            type=Protocol.TUIC,
            server="example.com",
            port=443,
            uuid="u",
            password="p",
            version=5,
            tls=TLSSettings(enabled=True),
        ),
        Protocol.ANYTLS: lambda: AnyTLSNode(
            name="anytls",
            type=Protocol.ANYTLS,
            server="example.com",
            port=443,
            password="p",
            tls=TLSSettings(enabled=True),
        ),
    }


def _transport_node(protocol: Protocol, network: str) -> Node:
    transport = TransportSettings(
        network=(
            Network(network) if network in {item.value for item in Network} else network
        ),
        path="/transport-sentinel",
        headers={"Host": "host.example.com"},
        host=["host.example.com"],
        grpc_service_name="grpc-sentinel",
    )
    common = {
        "name": f"{protocol.value}-{network}",
        "type": protocol,
        "server": "example.com",
        "port": 443,
        "transport": transport,
    }
    if protocol == Protocol.VMESS:
        return VmessNode(uuid="u", **common)
    if protocol == Protocol.VLESS:
        return VlessNode(uuid="u", **common)
    if protocol == Protocol.TROJAN:
        return TrojanNode(password="p", **common)
    raise AssertionError(f"No transport fixture for {protocol.value}")


def _declared_transport_cases() -> list[tuple[str, Protocol, str]]:
    cases = []
    for platform in LINK_PLATFORMS:
        capabilities = PLATFORM_CAPABILITIES[platform]
        for protocol in TRANSPORT_PROTOCOLS:
            protocol_caps = capabilities.get(protocol.value)
            if not protocol_caps:
                continue
            for network in sorted(protocol_caps.get("transports", set())):
                cases.append((platform, protocol, network))
    return cases


def test_capability_protocol_sections_match_declared_protocols():
    reserved = {"protocols", "global_features"}
    for platform, capabilities in PLATFORM_CAPABILITIES.items():
        protocol_sections = set(capabilities) - reserved
        assert protocol_sections == capabilities["protocols"], platform


def test_capability_tables_only_keep_runtime_feature_flags():
    runtime_features = {
        "tls",
        "h2-connect",
        "connect-udp",
        "obfs",
        "reality",
        "smux",
        "traffic-pattern",
    }
    for capabilities in PLATFORM_CAPABILITIES.values():
        assert set(capabilities["global_features"]) == {
            "tfo",
            "mptcp",
            "dialer_proxy",
        }
        for protocol in capabilities["protocols"]:
            assert capabilities[protocol].get("features", set()) <= runtime_features


def test_protocol_target_constraints_only_cover_registered_targets():
    for descriptor in protocol_registry.all():
        for target in descriptor.target_constraints:
            assert descriptor.protocol.value in PLATFORM_CAPABILITIES[target][
                "protocols"
            ]


def test_link_platform_protocols_have_builders_and_build_baseline_nodes():
    factories = _base_node_factories()
    declared_protocols = {
        Protocol(protocol)
        for platform in LINK_PLATFORMS
        for protocol in PLATFORM_CAPABILITIES[platform]["protocols"]
    }

    assert {codec.protocol for codec in link.all_codecs()} == declared_protocols
    assert declared_protocols <= set(factories)

    for platform in LINK_PLATFORMS:
        checker = NodeConversionService(platform)
        for protocol_name in PLATFORM_CAPABILITIES[platform]["protocols"]:
            protocol = Protocol(protocol_name)
            node = factories[protocol]()
            assert checker.check_node(node).supported, (platform, protocol.value)
            assert link.build_url(node), (platform, protocol.value)


def test_strong_nodes_must_have_valid_endpoint_and_required_credentials():
    node = ShadowsocksNode(
        name="invalid-ss",
        type=Protocol.SHADOWSOCKS,
        server="",
        port=0,
        cipher="aes-256-gcm",
        password="",
    )

    result = NodeConversionService("clash-meta").check_node(node)
    assert result.supported is False
    assert {warning.field for warning in result.warnings} == {
        "server",
        "port",
        "password",
    }


def test_platform_specific_typed_fields_are_not_silently_dropped():
    node = ShadowsocksNode(
        name="ss",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="p",
        surge_options=SurgePolicyOptions(test_timeout=5),
        shadow_tls=ShadowTLSSettings(password="shadow"),
    )

    result = NodeConversionService("mihomo").check_node(node)

    issue = next(
        warning
        for warning in result.warnings
        if warning.code == "conversion.unsupported-platform-field"
    )
    assert issue.severity.value == "warning"
    assert issue.field == "shadow_tls, surge_options"


def test_source_independent_base_fields_are_checked_for_link_targets():
    node = ShadowsocksNode(
        name="ss",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="p",
        interface_name="en0",
        routing_mark=123,
        users={"alice": {"password": "p2"}},
    )

    result = NodeConversionService("dae").check_node(node)

    issue = next(
        warning
        for warning in result.warnings
        if warning.code == "conversion.unsupported-platform-field"
    )
    assert issue.field == "interface_name, routing_mark, users"


def test_vmess_aead_is_only_serialized_by_surge():
    node = VmessNode(
        name="vmess",
        type=Protocol.VMESS,
        server="example.com",
        port=443,
        uuid="u",
        vmess_aead=True,
    )

    mihomo = NodeConversionService("mihomo").check_node(node)
    surge = NodeConversionService("surge").check_node(node)

    assert any(warning.field == "vmess_aead" for warning in mihomo.warnings)
    assert not any(warning.field == "vmess_aead" for warning in surge.warnings)


@pytest.mark.parametrize(
    "node, missing_field",
    [
        (
            TUICNode(
                name="tuic-missing-password",
                type=Protocol.TUIC,
                server="example.com",
                port=443,
                uuid="u",
            ),
            "password",
        ),
        (
            TUICNode(
                name="tuic-missing-credentials",
                type=Protocol.TUIC,
                server="example.com",
                port=443,
            ),
            "token",
        ),
    ],
)
def test_tuic_requires_a_complete_credential_form(node: TUICNode, missing_field: str):
    result = NodeConversionService("clash-meta").check_node(node)
    assert result.supported is False
    assert missing_field in {warning.field for warning in result.warnings}


@pytest.mark.parametrize(
    ("platform", "protocol", "network"), _declared_transport_cases()
)
def test_declared_link_transports_are_serialized(
    platform: str, protocol: Protocol, network: str
):
    node = _transport_node(protocol, network)
    assert NodeConversionService(platform).check_node(node).supported
    url = link.build_url(node)
    assert url is not None

    if protocol == Protocol.VMESS:
        payload = json.loads(base64.b64decode(url.removeprefix("vmess://")))
        assert payload["net"] == network
        if network in {"ws", "h2", "http"}:
            assert payload["path"] == "/transport-sentinel"
            assert payload["host"] == "host.example.com"
        elif network == "grpc":
            assert payload["path"] == "grpc-sentinel"
        return

    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    if protocol == Protocol.VLESS:
        assert query["type"] == [network]
    elif network == "tcp":
        assert "type" not in query
    else:
        assert query["type"] == [network]

    if network in {"ws", "h2", "http"}:
        assert query["path"] == ["/transport-sentinel"]
        assert query["host"] == ["host.example.com"]
    elif network == "grpc":
        assert query["serviceName"] == ["grpc-sentinel"]


def test_vless_reality_contract_uses_client_fingerprint():
    node = VlessNode(
        name="vless-reality",
        type=Protocol.VLESS,
        server="example.com",
        port=443,
        uuid="u",
        tls=TLSSettings(
            enabled=True,
            certificate_sha256="AA:BB",
            client_fingerprint="chrome",
            reality_opts={"public-key": "pk", "short-id": "sid"},
        ),
    )

    for platform in LINK_PLATFORMS:
        assert "reality" in PLATFORM_CAPABILITIES[platform]["vless"]["features"]
        assert NodeConversionService(platform).check_node(node).supported

    url = link.build_url(node)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["security"] == ["reality"]
    assert query["pbk"] == ["pk"]
    assert query["sid"] == ["sid"]
    assert query["fp"] == ["chrome"]


@pytest.mark.parametrize("protocol", [Protocol.VMESS, Protocol.TROJAN])
def test_undeclared_reality_is_rejected(protocol: Protocol):
    tls = TLSSettings(
        enabled=True,
        client_fingerprint="chrome",
        reality_opts={"public-key": "pk", "short-id": "sid"},
    )
    if protocol == Protocol.VMESS:
        node: Node = VmessNode(
            name="vmess-reality",
            type=protocol,
            server="example.com",
            port=443,
            uuid="u",
            tls=tls,
        )
    else:
        node = TrojanNode(
            name="trojan-reality",
            type=protocol,
            server="example.com",
            port=443,
            password="p",
            tls=tls,
        )

    for platform in LINK_PLATFORMS:
        assert (
            "reality"
            not in PLATFORM_CAPABILITIES[platform][protocol.value].get(
                "features", set()
            )
        )
        assert not NodeConversionService(platform).check_node(node).supported


def test_socks5_tls_is_rejected_by_link_platforms():
    node = Socks5Node(
        name="socks5-tls",
        type=Protocol.SOCKS5,
        server="example.com",
        port=443,
        tls=TLSSettings(enabled=True),
    )

    for platform in LINK_PLATFORMS:
        assert (
            "tls"
            not in PLATFORM_CAPABILITIES[platform]["socks5"].get(
                "features", set()
            )
        )
        assert not NodeConversionService(platform).check_node(node).supported
    assert link.build_url(node) is None


def test_hysteria2_obfs_declared_by_dae_is_serialized():
    node = Hysteria2Node(
        name="hysteria2-obfs",
        type=Protocol.HYSTERIA2,
        server="example.com",
        port=443,
        password="p",
        obfs="salamander",
        obfs_password="secret",
        tls=TLSSettings(enabled=True),
    )

    assert "obfs" in PLATFORM_CAPABILITIES["dae"]["hysteria2"]["features"]
    assert NodeConversionService("dae").check_node(node).supported
    url = link.build_url(node)
    assert url is not None
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["obfs"] == ["salamander"]
    assert query["obfs-password"] == ["secret"]


def test_tuic_versions_follow_credentials_and_capabilities():
    v5 = TUICNode(
        name="tuic-v5",
        type=Protocol.TUIC,
        server="example.com",
        port=443,
        uuid="u",
        password="p",
        version=5,
        tls=TLSSettings(enabled=True),
    )
    v4 = TUICNode(
        name="tuic-v4",
        type=Protocol.TUIC,
        server="example.com",
        port=443,
        token="token",
        version=4,
        tls=TLSSettings(enabled=True),
    )
    inferred_v4 = TUICNode(
        name="tuic-v4-inferred",
        type=Protocol.TUIC,
        server="example.com",
        port=443,
        token="token",
        tls=TLSSettings(enabled=True),
    )

    assert PLATFORM_CAPABILITIES["dae"]["tuic"]["versions"] == {5}
    checker = NodeConversionService("dae")
    assert checker.check_node(v5).supported
    assert not checker.check_node(v4).supported
    assert not checker.check_node(inferred_v4).supported

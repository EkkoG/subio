import json
from pathlib import Path

import pytest

import subio_v2.protocols as registry
from subio_v2.capabilities.definitions import PLATFORM_CAPABILITIES
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.model.nodes import (
    DNSNode,
    GostRelayNode,
    MieruNode,
    OpenVPNNode,
    Protocol,
    RematchNode,
    RejectMode,
    RejectNode,
    ShadowQUICNode,
    SourcePassthroughNode,
)
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.surge import SurgeParser


SCHEMA_SNAPSHOT = (
    Path(__file__).parent / "fixtures/mihomo/schema/proxies-88d5239.json"
)


def test_mihomo_schema_types_have_explicit_registry_strategies():
    snapshot = json.loads(SCHEMA_SNAPSHOT.read_text())
    descriptors = list(registry.all())
    known_types = {
        descriptor.clash_type
        for descriptor in descriptors
        if not descriptor.dynamic_clash_type
        and descriptor.supports_dialect("mihomo")
    }

    assert known_types == set(snapshot["proxy_types"])
    assert len(known_types) == 26
    assert registry.get(Protocol.MIERU).node_class is MieruNode
    assert registry.get(Protocol.MIERU).passthrough is False
    assert registry.get(Protocol.REJECT).node_class is RejectNode
    assert registry.get(Protocol.REJECT).requires_endpoint is False
    assert registry.get(Protocol.DNS).node_class is DNSNode
    assert registry.get(Protocol.DNS).passthrough is False
    assert registry.get(Protocol.SHADOWQUIC).node_class is ShadowQUICNode
    assert registry.get(Protocol.SHADOWQUIC).passthrough is False
    assert registry.get(Protocol.OPENVPN).node_class is OpenVPNNode
    assert registry.get(Protocol.OPENVPN).passthrough is False
    registered_protocols = {
        descriptor.protocol.value
        for descriptor in descriptors
        if descriptor.supports_dialect("mihomo")
    }
    assert PLATFORM_CAPABILITIES["mihomo"]["protocols"] == registered_protocols


def test_mihomo_dns_outbound_uses_strong_ir_and_smux():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "dns-out",
                    "type": "dns",
                    "dialer-proxy": "upstream",
                    "smux": {"enabled": True, "max-connections": 3},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, DNSNode)
    assert node.server is None
    assert node.port is None
    assert node.dialer_proxy == "upstream"
    assert node.smux.max_connections == 3
    emission = ClashEmitter(platform="mihomo").emit_result([node])
    assert emission.errors == []
    assert emission.content["proxies"][0]["smux"]["max-connections"] == 3


def test_mihomo_rematch_uses_strong_ir_and_requires_a_target():
    parser = ClashParser()
    node = parser.parse_result(
        {
            "proxies": [
                {
                    "name": "rematch",
                    "type": "rematch",
                    "target-rematch-name": "streaming",
                    "target-sub-rule": "media",
                    "smux": {"enabled": True},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, RematchNode)
    assert node.target_rematch_name == "streaming"
    assert node.target_sub_rule == "media"
    emission = ClashEmitter(platform="mihomo").emit_result([node])
    assert emission.errors == []
    assert emission.content["proxies"][0]["target-sub-rule"] == "media"

    invalid = parser.parse_result(
        {"proxies": [{"name": "invalid", "type": "rematch"}]}
    ).nodes[0]
    invalid_emission = ClashEmitter(platform="mihomo").emit_result([invalid])
    assert invalid_emission.content["proxies"] == []
    assert invalid_emission.errors[0].field == "target_rematch_name"


def test_mihomo_gost_relay_uses_strong_ir_for_tls_and_mux():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "gost",
                    "type": "gost-relay",
                    "server": "gost.example.com",
                    "port": 443,
                    "forward": True,
                    "mux": True,
                    "username": "user",
                    "password": "secret",
                    "tls": True,
                    "sni": "relay.example.com",
                    "fingerprint": "AA:BB",
                    "client-fingerprint": "chrome",
                    "smux": {"enabled": True},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, GostRelayNode)
    assert node.forward is True
    assert node.mux is True
    assert node.tls.server_name == "relay.example.com"
    assert node.tls.certificate_sha256 == "AA:BB"
    emission = ClashEmitter(platform="mihomo").emit_result([node])
    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy["forward"] is True
    assert proxy["mux"] is True
    assert proxy["fingerprint"] == "AA:BB"


def test_mihomo_shadowquic_uses_strong_ir_for_quic_tuning():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "shadowquic",
                    "type": "shadowquic",
                    "server": "quic.example.com",
                    "port": 443,
                    "username": "user",
                    "password": "secret",
                    "sni": "edge.example.com",
                    "alpn": ["h3"],
                    "quic-versions": ["v1", "v2"],
                    "udp-over-stream": True,
                    "zero-rtt": True,
                    "keep-alive-interval": 15000,
                    "congestion-controller": "bbr",
                    "up": "20 Mbps",
                    "down": "100 Mbps",
                    "cwnd": 64,
                    "bbr-profile": "aggressive",
                    "recv-window-conn": 1048576,
                    "recv-window": 2097152,
                    "disable-mtu-discovery": True,
                    "max-datagram-frame-size": 1350,
                    "max-open-streams": 512,
                    "smux": {"enabled": True},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, ShadowQUICNode)
    assert node.quic_versions == ["v1", "v2"]
    assert node.tls.server_name == "edge.example.com"
    assert node.max_open_streams == 512
    emission = ClashEmitter(platform="mihomo").emit_result([node])
    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy["quic-versions"] == ["v1", "v2"]
    assert proxy["max-datagram-frame-size"] == 1350

    invalid = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "invalid",
                    "type": "shadowquic",
                    "server": "quic.example.com",
                    "port": 443,
                    "congestion-controller": "unknown",
                }
            ]
        }
    ).nodes[0]
    invalid_emission = ClashEmitter(platform="mihomo").emit_result([invalid])
    assert invalid_emission.errors[0].field == "congestion_controller"


def test_mihomo_openvpn_uses_strong_ir_for_credentials_and_runtime_options():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "openvpn",
                    "type": "openvpn",
                    "server": "vpn.example.com",
                    "port": 1194,
                    "proto": "tcp-client",
                    "cipher": "AES-256-GCM",
                    "data-ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
                    "ca": "ca-content",
                    "cert": "cert-content",
                    "key": "key-content",
                    "tls-crypt-v2": "tls-key",
                    "key-direction": 1,
                    "peer-info": {"IV_VER": "3.10"},
                    "ping": 10,
                    "ping-restart": 30,
                    "handshake-timeout": 15,
                    "mtu": 1400,
                    "remote-dns-resolve": True,
                    "dns": ["1.1.1.1"],
                    "smux": {"enabled": True},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, OpenVPNNode)
    assert node.proto == "tcp-client"
    assert node.private_key == "key-content"
    assert node.key_direction == "1"
    assert node.dns_servers == ["1.1.1.1"]
    emission = ClashEmitter(platform="mihomo").emit_result([node])
    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy["cert"] == "cert-content"
    assert proxy["key"] == "key-content"
    assert proxy["key-direction"] == "1"
    assert proxy["smux"]["enabled"] is True


@pytest.mark.parametrize(
    "overrides, expected_fields",
    [
        ({"ca": ""}, {"ca"}),
        ({"cert": "cert", "username": "user"}, {"certificate"}),
        ({"username": None}, {"username"}),
        (
            {"tls-auth": "a", "tls-crypt": "b"},
            {"tls_auth"},
        ),
        ({"proto": "invalid"}, {"proto"}),
        ({"data-ciphers": ["invalid"]}, {"data_ciphers"}),
    ],
)
def test_mihomo_openvpn_rejects_invalid_schema_combinations(
    overrides, expected_fields
):
    proxy = {
        "name": "openvpn-invalid",
        "type": "openvpn",
        "server": "vpn.example.com",
        "port": 1194,
        "ca": "ca-content",
        "username": "user",
    }
    proxy.update(overrides)
    node = ClashParser().parse_result({"proxies": [proxy]}).nodes[0]

    emission = ClashEmitter(platform="mihomo").emit_result([node])

    assert emission.content["proxies"] == []
    assert expected_fields <= {issue.field for issue in emission.errors}


@pytest.mark.parametrize(
    "mode",
    [RejectMode.DROP, RejectMode.NO_DROP, RejectMode.TINYGIF],
)
def test_surge_only_reject_modes_are_rejected_by_mihomo(mode):
    node = SurgeParser().parse_result(f"deny = {mode.value}").nodes[0]

    emission = ClashEmitter(platform="mihomo").emit_result([node])

    assert emission.content["proxies"] == []
    assert len(emission.errors) == 1
    assert emission.errors[0].field == "mode"
    assert emission.errors[0].code == "conversion.unsupported-protocol-variant"


def test_mihomo_reject_smux_uses_existing_strong_setting():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "reject-smux",
                    "type": "reject",
                    "smux": {"enabled": True, "max-connections": 6},
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, RejectNode)
    assert node.smux.enabled is True
    assert node.smux.max_connections == 6
    proxy = ClashEmitter(platform="mihomo").emit_result([node]).content[
        "proxies"
    ][0]
    assert proxy == {
        "name": "reject-smux",
        "type": "reject",
        "smux": {
            "enabled": True,
            "protocol": "smux",
            "max-connections": 6,
            "min-streams": 4,
            "max-streams": 0,
            "padding": False,
        },
    }


def test_future_unknown_type_uses_source_bound_passthrough():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "future",
                    "type": "future-protocol",
                    "server": "example.com",
                    "port": 443,
                    "future": True,
                }
            ]
        }
    ).nodes[0]

    assert isinstance(node, SourcePassthroughNode)
    assert node.type is Protocol.SOURCE_PASSTHROUGH
    assert node.original_type == "future-protocol"
    assert registry.get(Protocol.SOURCE_PASSTHROUGH) is None

import pytest

from subio_v2.adapters.clash_family.emitter import ClashEmitter
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.target import TargetValidationService as NodeConversionService
from subio_v2.core.nodes import (
    MieruHandshakeMode,
    MieruMultiplexing,
    MieruNode,
    MieruTransport,
    Protocol,
)


def test_mihomo_mieru_port_range_round_trip_uses_strong_ir():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "mieru-range",
                    "type": "mieru",
                    "server": "example.com",
                    "port-range": "2000-2010",
                    "transport": "UDP",
                    "udp": True,
                    "username": "user",
                    "password": "secret",
                    "multiplexing": "MULTIPLEXING_HIGH",
                    "handshake-mode": "HANDSHAKE_NO_WAIT",
                    "traffic-pattern": "dHJhZmZpYw==",
                    "smux": {"enabled": True, "max-connections": 8},
                }
            ]
        }
    )

    assert parsed.issues == []
    assert len(parsed.nodes) == 1
    node = parsed.nodes[0]
    assert isinstance(node, MieruNode)
    assert node.port is None
    assert node.port_range == "2000-2010"
    assert node.transport is MieruTransport.UDP
    assert node.multiplexing is MieruMultiplexing.HIGH
    assert node.handshake_mode is MieruHandshakeMode.NO_WAIT
    assert node.traffic_pattern == "dHJhZmZpYw=="
    assert node.smux.enabled is True
    assert node.extra == {}

    emission = ClashEmitter(platform="clash-meta").emit_result([node])
    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert "port" not in proxy
    assert proxy["port-range"] == "2000-2010"
    assert proxy["transport"] == "UDP"
    assert proxy["multiplexing"] == "MULTIPLEXING_HIGH"
    assert proxy["handshake-mode"] == "HANDSHAKE_NO_WAIT"
    assert proxy["traffic-pattern"] == "dHJhZmZpYw=="
    assert proxy["smux"]["max-connections"] == 8


def test_mihomo_mieru_accepts_single_port_and_canonicalizes_range_in_port():
    nodes = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "single",
                    "type": "mieru",
                    "server": "example.com",
                    "port": 2999,
                    "transport": "TCP",
                    "username": "user",
                    "password": "secret",
                },
                {
                    "name": "range-in-port",
                    "type": "mieru",
                    "server": "example.com",
                    "port": "3000-3010",
                    "transport": "TCP",
                    "username": "user",
                    "password": "secret",
                },
            ]
        }
    ).nodes

    assert nodes[0].port == 2999
    assert nodes[0].port_range is None
    assert nodes[1].port is None
    assert nodes[1].port_range == "3000-3010"

    proxies = ClashEmitter(platform="clash-meta").emit_result(nodes).content["proxies"]
    assert proxies[0]["port"] == 2999
    assert "port-range" not in proxies[0]
    assert "port" not in proxies[1]
    assert proxies[1]["port-range"] == "3000-3010"


@pytest.mark.parametrize(
    "changes, expected_field",
    [
        ({"port": None, "port_range": None}, "port_range"),
        ({"port": 2999, "port_range": "3000-3010"}, "port_range"),
        ({"port": None, "port_range": "3010-3000"}, "port_range"),
        ({"username": ""}, "username"),
        ({"password": ""}, "password"),
    ],
)
def test_mieru_capability_rejects_invalid_required_fields(changes, expected_field):
    kwargs = {
        "name": "mieru",
        "type": Protocol.MIERU,
        "server": "example.com",
        "port": 2999,
        "transport": MieruTransport.TCP,
        "username": "user",
        "password": "secret",
    }
    kwargs.update(changes)
    node = MieruNode(**kwargs)

    result = NodeConversionService("clash-meta").check_node(node)

    assert result.supported is False
    assert expected_field in {warning.field for warning in result.warnings}


def test_mieru_rejects_values_outside_mihomo_schema_domains():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "invalid",
                    "type": "mieru",
                    "server": "example.com",
                    "port": 2999,
                    "transport": "tcp",
                    "username": "user",
                    "password": "secret",
                }
            ]
        }
    )

    assert parsed.nodes == []
    assert len(parsed.issues) == 1
    assert parsed.issues[0].code == "parse.node"


def test_mihomo_snell_maps_reuse_and_rejects_surge_udp_port():
    mihomo_node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "snell-reuse",
                    "type": "snell",
                    "server": "example.com",
                    "port": 443,
                    "psk": "secret",
                    "version": 4,
                    "reuse": False,
                }
            ]
        }
    ).nodes[0]
    assert mihomo_node.reuse is False
    assert "reuse" not in mihomo_node.extra
    proxy = ClashEmitter(platform="clash-meta").emit_result([mihomo_node]).content[
        "proxies"
    ][0]
    assert proxy["reuse"] is False

    surge_node = SurgeParser().parse_result(
        "snell-udp = snell, example.com, 443, psk=secret, version=4, udp-port=8443"
    ).nodes[0]
    emission = ClashEmitter(platform="clash-meta").emit_result([surge_node])
    assert emission.content["proxies"] == []
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        and issue.field == "udp_port"
        for issue in emission.errors
    )


def test_mihomo_snell_reuse_follows_schema_version_domain():
    node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "snell-v3-reuse",
                    "type": "snell",
                    "server": "example.com",
                    "port": 443,
                    "psk": "secret",
                    "version": 3,
                    "reuse": True,
                }
            ]
        }
    ).nodes[0]

    result = NodeConversionService("clash-meta").check_node(node)

    assert result.supported is False
    assert "reuse" in {warning.field for warning in result.warnings}

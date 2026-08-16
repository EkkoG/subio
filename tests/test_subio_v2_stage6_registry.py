import json
from pathlib import Path

import pytest

import subio_v2.protocols as registry
from subio_v2.capabilities.definitions import PLATFORM_CAPABILITIES
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.model.nodes import (
    ClashPassthroughNode,
    DNSNode,
    MieruNode,
    Protocol,
    RematchNode,
    RejectMode,
    RejectNode,
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
    registered_protocols = {
        descriptor.protocol.value
        for descriptor in descriptors
        if descriptor.supports_dialect("mihomo")
    }
    assert PLATFORM_CAPABILITIES["mihomo"]["protocols"] == registered_protocols


@pytest.mark.parametrize(
    ("protocol", "clash_type"),
    [
        (Protocol.GOST_RELAY, "gost-relay"),
        (Protocol.SHADOWQUIC, "shadowquic"),
    ],
)
def test_new_mihomo_only_types_use_explicit_passthrough(protocol, clash_type):
    descriptor = registry.get(protocol)

    assert descriptor is not None
    assert descriptor.clash_type == clash_type
    assert descriptor.passthrough is True
    assert descriptor.dynamic_clash_type is False


def test_new_mihomo_only_passthrough_types_round_trip_without_dynamic_fallback():
    source = {
        "proxies": [
            {
                "name": "gost",
                "type": "gost-relay",
                "server": "gost.example.com",
                "port": 443,
                "forward": True,
                "tls": True,
                "username": "user",
                "password": "secret",
            },
            {
                "name": "shadowquic",
                "type": "shadowquic",
                "server": "quic.example.com",
                "port": 443,
                "username": "user",
                "password": "secret",
                "zero-rtt": True,
            },
        ]
    }

    nodes = ClashParser().parse_result(source).nodes

    assert [node.type for node in nodes] == [
        Protocol.GOST_RELAY,
        Protocol.SHADOWQUIC,
    ]
    assert all(isinstance(node, ClashPassthroughNode) for node in nodes)
    emission = ClashEmitter(platform="mihomo").emit_result(nodes)
    assert emission.errors == []
    assert emission.content == source


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

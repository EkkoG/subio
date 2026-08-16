import json
from pathlib import Path

import pytest

import subio_v2.protocols as registry
from subio_v2.capabilities.definitions import PLATFORM_CAPABILITIES
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.model.nodes import (
    ClashPassthroughNode,
    MieruNode,
    Protocol,
    RejectMode,
    RejectNode,
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
        (Protocol.REMATCH, "rematch"),
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
                "name": "rematch",
                "type": "rematch",
                "target-rematch-name": "streaming",
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
        Protocol.REMATCH,
        Protocol.SHADOWQUIC,
    ]
    assert all(isinstance(node, ClashPassthroughNode) for node in nodes)
    emission = ClashEmitter(platform="mihomo").emit_result(nodes)
    assert emission.errors == []
    assert emission.content == source


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


def test_future_unknown_type_still_uses_dynamic_passthrough():
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

    assert node.type is Protocol.CLASH_UNKNOWN
    assert node.clash_type == "future-protocol"
    assert registry.get(Protocol.CLASH_UNKNOWN).dynamic_clash_type is True

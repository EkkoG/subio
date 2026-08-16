from subio_v2.capabilities.definitions import PLATFORM_CAPABILITIES
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.model.nodes import (
    JuicityNode,
    MieruMultiplexing,
    MieruNode,
    MieruTransport,
    Protocol,
)
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser


def test_stash_mieru_round_trips_and_converts_transport_value_domain():
    source = {
        "proxies": [
            {
                "name": "mieru",
                "type": "mieru",
                "server": "mieru.example.com",
                "port-range": "2012-2022",
                "transport": "tcp",
                "username": "user",
                "password": "secret",
            }
        ]
    }

    node = StashParser().parse_result(source).nodes[0]

    assert isinstance(node, MieruNode)
    assert node.transport is MieruTransport.TCP
    stash = StashEmitter().emit_result([node])
    assert stash.errors == []
    assert stash.content == source

    mihomo = ClashEmitter("clash-meta").emit_result([node])
    assert mihomo.errors == []
    assert mihomo.content["proxies"][0]["transport"] == "TCP"


def test_mihomo_mieru_emits_stash_lowercase_and_rejects_private_semantics():
    common = {
        "name": "mieru",
        "type": Protocol.MIERU,
        "server": "mieru.example.com",
        "port": 2012,
        "transport": MieruTransport.TCP,
        "username": "user",
        "password": "secret",
    }
    node = MieruNode(**common)

    emission = StashEmitter().emit_result([node])

    assert emission.errors == []
    assert emission.content["proxies"][0]["transport"] == "tcp"

    node.multiplexing = MieruMultiplexing.HIGH
    rejected = StashEmitter().emit_result([node])
    assert rejected.supported_nodes == []
    assert rejected.errors[0].field == "multiplexing"
    assert rejected.errors[0].code == "conversion.unsupported-protocol-variant"


def test_stash_mieru_rejects_undocumented_udp_transport():
    node = StashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "mieru",
                    "type": "mieru",
                    "server": "mieru.example.com",
                    "port": 2012,
                    "transport": "udp",
                    "username": "user",
                    "password": "secret",
                }
            ]
        }
    ).nodes[0]

    emission = StashEmitter().emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].field == "transport"


def test_stash_juicity_is_strong_and_round_trips():
    source = {
        "proxies": [
            {
                "name": "juicity",
                "type": "juicity",
                "server": "juicity.example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "password": "secret",
                "sni": "juicity.example.com",
                "alpn": ["h3"],
                "skip-cert-verify": True,
                "server-cert-fingerprint": "AA:BB",
            }
        ]
    }

    node = StashParser().parse_result(source).nodes[0]

    assert isinstance(node, JuicityNode)
    assert node.tls.enabled is True
    assert node.tls.certificate_sha256 == "AA:BB"
    emission = StashEmitter().emit_result([node])
    assert emission.errors == []
    assert emission.content == source
    assert StashParser().parse_result(emission.content).nodes == [node]


def test_juicity_is_stash_only_and_never_becomes_mihomo_strong_semantics():
    node = JuicityNode(
        name="juicity",
        type=Protocol.JUICITY,
        server="juicity.example.com",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
        password="secret",
    )

    emission = ClashEmitter("clash-meta").emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].field == "type"

    parsed_as_mihomo = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "future-juicity",
                    "type": "juicity",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "u",
                    "password": "p",
                }
            ]
        }
    )
    assert parsed_as_mihomo.nodes == []
    assert parsed_as_mihomo.issues[0].severity.value == "error"
    assert "Known proxy type 'juicity'" in parsed_as_mihomo.issues[0].message


def test_stage10_capability_is_complete_for_mieru_and_juicity():
    assert {"mieru", "juicity"} <= PLATFORM_CAPABILITIES["stash"]["protocols"]
    assert "juicity" not in PLATFORM_CAPABILITIES["mihomo"]["protocols"]

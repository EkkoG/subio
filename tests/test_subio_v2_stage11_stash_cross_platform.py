import pytest

from tests.support_target_views import all_platform_capabilities
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.model.nodes import (
    MasqueMode,
    MasqueNode,
    Protocol,
    TailscaleNode,
    TrustTunnelNode,
)
from subio_v2.model.records import NodeRecord

PLATFORM_CAPABILITIES = all_platform_capabilities()
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser

STAGE11_PROTOCOLS = {"tailscale", "masque", "trusttunnel"}


def _stage11_stash_source():
    return {
        "proxies": [
            {
                "name": "tailnet-auto",
                "type": "tailscale",
                "hostname": "stash-client",
                "control-url": "https://control.example.com",
                "ephemeral": True,
            },
            {
                "name": "masque",
                "type": "masque",
                "server": "masque.example.com",
                "port": 443,
                "private-key": "private",
                "public-key": "public",
                "ip": "172.16.0.2/32",
                "dns": ["1.1.1.1"],
                "network": "h3",
                "sni": "masque.example.com",
                "connect-uri": "https://masque.example.com/.well-known/masque",
                "mtu": 1280,
                "keepalive": 30,
            },
            {
                "name": "trust",
                "type": "trusttunnel",
                "server": "trust.example.com",
                "port": 443,
                "username": "user",
                "password": "secret",
                "quic": False,
                "sni": "trust.example.com",
                "alpn": ["h2"],
                "skip-cert-verify": True,
                "server-cert-fingerprint": "AA:BB",
            },
        ]
    }


def test_stage11_stash_protocols_round_trip_documented_fields():
    source = _stage11_stash_source()
    parsed = StashParser().parse_result(source)

    assert parsed.issues == []
    assert {node.type.value for node in parsed.nodes} == STAGE11_PROTOCOLS
    tailscale = parsed.nodes[0]
    assert isinstance(tailscale, TailscaleNode)
    assert tailscale.exit_node is None
    assert tailscale.exit_node_auto_fallback is True
    masque = parsed.nodes[1]
    assert isinstance(masque, MasqueNode)
    assert masque.mode is MasqueMode.CONNECT_IP
    assert masque.transport == "h3"
    assert masque.connect_uri == "https://masque.example.com/.well-known/masque"
    assert masque.extra == {"keepalive": 30}

    emission = StashEmitter().emit_result(parsed.nodes)

    assert emission.errors == []
    assert emission.content == source
    reparsed = StashParser().parse_result(emission.content)
    assert reparsed.issues == []
    assert reparsed.nodes == parsed.nodes


@pytest.mark.parametrize(
    ("proxy", "expected"),
    [
        (
            {
                "name": "wireguard",
                "type": "wireguard",
                "server": "wireguard.example.com",
                "port": 51820,
                "ip": "10.0.0.2",
                "private-key": "private",
                "public-key": "public",
                "keepalive": 45,
            },
            {"persistent-keepalive": 45},
        ),
        (
            {
                "name": "ssh",
                "type": "ssh",
                "server": "ssh.example.com",
                "port": 22,
                "user": "root",
                "password": "secret",
            },
            {"username": "root"},
        ),
        (
            {
                "name": "tuic",
                "type": "tuic",
                "server": "tuic.example.com",
                "port": 443,
                "version": 5,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "password": "secret",
            },
            {"uuid": "00000000-0000-0000-0000-000000000001"},
        ),
        (
            {
                "name": "hysteria2",
                "type": "hysteria2",
                "server": "hysteria2.example.com",
                "port": 443,
                "auth": "secret",
                "obfs": "salamander",
                "obfs-password": "obfs-secret",
            },
            {"password": "secret", "obfs": "salamander"},
        ),
        (
            {
                "name": "tailscale",
                "type": "tailscale",
                "auth-key": "tskey-auth-example",
                "hostname": "stash-client",
                "exit-node": "100.64.0.10",
            },
            {"hostname": "stash-client", "exit-node": "100.64.0.10"},
        ),
        (
            {
                "name": "masque",
                "type": "masque",
                "server": "masque.example.com",
                "port": 443,
                "private-key": "private",
                "public-key": "public",
                "ipv6": "fd00::2/128",
                "network": "h2",
                "connect-uri": "https://masque.example.com/connect-ip",
            },
            {
                "network": "h2",
                "uri": "https://masque.example.com/connect-ip",
            },
        ),
        (
            {
                "name": "trust",
                "type": "trusttunnel",
                "server": "trust.example.com",
                "port": 443,
                "username": "user",
                "password": "secret",
                "quic": True,
                "server-cert-fingerprint": "AA:BB",
            },
            {"quic": True, "fingerprint": "AA:BB"},
        ),
    ],
)
def test_stash_to_mihomo_cross_platform_golden_matrix(proxy, expected):
    node = StashParser().parse_result({"proxies": [proxy]}).nodes[0]
    node.source_provider = "stash-provider"

    emission = ClashEmitter("clash-meta").emit_result([node])

    assert emission.errors == []
    output = emission.content["proxies"][0]
    for key, value in expected.items():
        assert output[key] == value


def test_tailscale_omitted_exit_node_semantics_are_not_guessed():
    stash_node = StashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "stash-auto",
                    "type": "tailscale",
                    "auth-key": "tskey-auth-example",
                }
            ]
        }
    ).nodes[0]
    stash_node.source_provider = "stash-provider"

    to_mihomo = ClashEmitter("clash-meta").emit_result([stash_node])

    assert to_mihomo.supported_nodes == []
    issue = to_mihomo.errors[0]
    assert issue.protocol == "tailscale"
    assert issue.field == "exit_node_auto_fallback"
    assert issue.source == "stash-provider"
    assert issue.target == "mihomo"

    mihomo_node = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "mihomo-no-exit",
                    "type": "tailscale",
                    "auth-key": "tskey-auth-example",
                }
            ]
        }
    ).nodes[0]
    mihomo_node.source_provider = "mihomo-provider"

    to_stash = StashEmitter().emit_result([mihomo_node])

    assert to_stash.supported_nodes == []
    issue = to_stash.errors[0]
    assert issue.protocol == "tailscale"
    assert issue.field == "exit_node_auto_fallback"
    assert issue.source == "mihomo-provider"
    assert issue.target == "stash"


@pytest.mark.parametrize(
    "node",
    [
        MasqueNode(
            name="mihomo-l4",
            type=Protocol.MASQUE,
            server="masque.example.com",
            port=443,
            udp=False,
            mode=MasqueMode.H3_L4_PROXY,
            private_key="private",
            public_key="public",
            record=NodeRecord(source_provider="mihomo-provider"),
        ),
        MasqueNode(
            name="surge-forward",
            type=Protocol.MASQUE,
            server="masque.example.com",
            port=443,
            mode=MasqueMode.FORWARD_PROXY,
            username="user",
            password="secret",
            record=NodeRecord(source_provider="surge-provider"),
        ),
    ],
)
def test_stash_rejects_incompatible_masque_profiles(node):
    emission = StashEmitter().emit_result([node])

    assert emission.supported_nodes == []
    issue = emission.errors[0]
    assert issue.protocol == "masque"
    assert issue.field == "mode"
    assert issue.source == node.source_provider
    assert issue.target == "stash"
    assert issue.code == "conversion.unsupported-protocol-variant"


def test_stash_trust_tunnel_diagnoses_platform_only_semantics():
    unsupported = TrustTunnelNode(
        name="surge-ws",
        type=Protocol.TRUSTTUNNEL,
        server="trust.example.com",
        port=443,
        username="user",
        password="secret",
        websocket=True,
        headers="X-Test: value",
        record=NodeRecord(source_provider="surge-provider"),
    )

    rejected = StashEmitter().emit_result([unsupported])

    assert rejected.supported_nodes == []
    fields = {issue.field for issue in rejected.errors}
    assert {"headers", "websocket"} <= fields
    assert all(issue.protocol == "trusttunnel" for issue in rejected.errors)
    assert all(issue.source == "surge-provider" for issue in rejected.errors)
    assert all(issue.target == "stash" for issue in rejected.errors)

    lossy = TrustTunnelNode(
        name="mihomo-health",
        type=Protocol.TRUSTTUNNEL,
        server="trust.example.com",
        port=443,
        username="user",
        password="secret",
        health_check=True,
        record=NodeRecord(source_provider="mihomo-provider"),
    )
    warned = StashEmitter().emit_result([lossy])

    assert warned.errors == []
    issue = next(issue for issue in warned.issues if issue.field == "health_check")
    assert issue.protocol == "trusttunnel"
    assert issue.source == "mihomo-provider"
    assert issue.target == "stash"
    assert issue.code == "conversion.unconsumed-source-field"


def test_stage11_stash_capability_contains_twenty_protocols():
    protocols = PLATFORM_CAPABILITIES["stash"]["protocols"]

    assert STAGE11_PROTOCOLS <= protocols
    assert len(protocols) == 20

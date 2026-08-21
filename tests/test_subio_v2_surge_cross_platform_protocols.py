from subio_v2.adapters.clash_family.emitter import ClashEmitter
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.core.nodes import (
    DirectNode,
    MasqueMode,
    MasqueNode,
    RejectMode,
    RejectNode,
    TailscaleNode,
    TrustTunnelNode,
)


def test_surge_tailscale_common_fields_emit_to_mihomo():
    result = SurgeParser().parse_result(
        """
[Proxy]
Tailnet = tailscale, section-name=office, underlying-proxy=upstream

[Tailscale office]
auth-key = tskey-auth-example
hostname = surge-client
control-url = https://control.example.com
exit-node = 100.64.0.10
"""
    )

    assert result.issues == []
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert isinstance(node, TailscaleNode)

    emission = ClashEmitter().emit_result(result.nodes)

    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy == {
        "name": "Tailnet",
        "type": "tailscale",
        "udp": True,
        "dialer-proxy": "upstream",
        "hostname": "surge-client",
        "auth-key": "tskey-auth-example",
        "control-url": "https://control.example.com",
        "ephemeral": False,
        "accept-routes": False,
        "exit-node": "100.64.0.10",
        "exit-node-allow-lan-access": False,
    }


def test_mihomo_tailscale_common_fields_emit_to_surge_section():
    result = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "Tailnet",
                    "type": "tailscale",
                    "hostname": "mihomo-client",
                    "auth-key": "tskey-auth-example",
                    "control-url": "https://control.example.com",
                    "exit-node": "100.64.0.10",
                    "udp": True,
                    "dialer-proxy": "upstream",
                }
            ]
        }
    )

    emission = SurgeEmitter().emit_result(result.nodes)

    assert emission.errors == []
    assert (
        "Tailnet = tailscale, section-name=Tailnet, underlying-proxy=upstream"
        in emission.content
    )
    assert "[Tailscale Tailnet]" in emission.content
    assert "auth-key = tskey-auth-example" in emission.content
    assert "hostname = mihomo-client" in emission.content
    assert "control-url = https://control.example.com" in emission.content
    assert "exit-node = 100.64.0.10" in emission.content


def test_tailscale_local_interactive_state_and_auto_exit_modes_are_not_guessed():
    surge = SurgeParser().parse_result(
        """
[Proxy]
Tailnet = tailscale, section-name=office

[Tailscale office]
interactive-login = true
hostname = surge-client
"""
    )
    to_mihomo = ClashEmitter().emit_result(surge.nodes)
    assert to_mihomo.supported_nodes == []
    assert to_mihomo.errors[0].code == "conversion.unsupported-auth-profile"

    mihomo = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "Tailnet",
                    "type": "tailscale",
                    "auth-key": "key",
                    "exit-node": "auto:any",
                }
            ]
        }
    )
    to_surge = SurgeEmitter().emit_result(mihomo.nodes)
    assert to_surge.supported_nodes == []
    assert to_surge.errors[0].code == "conversion.unsupported-protocol-variant"


def test_trust_tunnel_maps_h3_tls_and_multiplexing_to_mihomo():
    parsed = SurgeParser().parse_result(
        """
[Proxy]
trust = trust-tunnel, trust.example.com, 443, username=user, password=pass, max-streams=5, h3=true, sni=trust.example.com, skip-cert-verify=true, server-cert-fingerprint-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"""
    )

    assert isinstance(parsed.nodes[0], TrustTunnelNode)
    emission = ClashEmitter().emit_result(parsed.nodes)

    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy["type"] == "trusttunnel"
    assert proxy["udp"] is False
    assert proxy["quic"] is True
    assert proxy["max-streams"] == 5
    assert proxy["sni"] == "trust.example.com"
    assert proxy["skip-cert-verify"] is True
    assert proxy["fingerprint"] == (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )


def test_mihomo_trust_tunnel_without_udp_emits_to_surge():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "trust",
                    "type": "trusttunnel",
                    "server": "trust.example.com",
                    "port": 443,
                    "username": "user",
                    "password": "pass",
                    "udp": False,
                    "quic": True,
                    "max-streams": 4,
                    "sni": "trust.example.com",
                    "name-cert-verify": "verify.example.com",
                }
            ]
        }
    )

    emission = SurgeEmitter().emit_result(parsed.nodes)

    assert emission.errors == []
    assert "trust = trust-tunnel, trust.example.com, 443" in emission.content
    assert "username=user" in emission.content
    assert "password=pass" in emission.content
    assert "max-streams=4" in emission.content
    assert "h3=true" in emission.content
    assert "sni=trust.example.com" in emission.content
    assert "server-cert-verify-name=verify.example.com" in emission.content


def test_mihomo_trust_tunnel_udp_is_rejected_by_surge():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "trust",
                    "type": "trusttunnel",
                    "server": "trust.example.com",
                    "port": 443,
                    "username": "user",
                    "password": "pass",
                    "udp": True,
                }
            ]
        }
    )

    emission = SurgeEmitter().emit_result(parsed.nodes)

    assert emission.supported_nodes == []
    assert emission.errors[0].code == "conversion.unsupported-protocol-variant"


def test_mihomo_masque_modes_round_trip_as_strong_nodes():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "connect-ip",
                    "type": "masque",
                    "server": "masque.example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                    "ip": "172.16.0.2/32",
                    "network": "h2",
                    "udp": True,
                    "handshake-timeout": 30,
                },
                {
                    "name": "l4",
                    "type": "masque",
                    "server": "masque.example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                    "network": "h3-l4proxy",
                    "udp": False,
                },
                {
                    "name": "future-network",
                    "type": "masque",
                    "server": "masque.example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                    "ip": "172.16.0.3/32",
                    "network": "future-transport",
                    "udp": False,
                },
            ]
        }
    )

    assert parsed.issues == []
    assert all(isinstance(node, MasqueNode) for node in parsed.nodes)
    assert parsed.nodes[0].mode == MasqueMode.CONNECT_IP
    assert parsed.nodes[0].transport == "h2"
    assert parsed.nodes[1].mode == MasqueMode.H3_L4_PROXY
    assert parsed.nodes[2].transport == "future-transport"

    emission = ClashEmitter().emit_result(parsed.nodes)

    assert emission.errors == []
    by_name = {proxy["name"]: proxy for proxy in emission.content["proxies"]}
    assert by_name["connect-ip"]["network"] == "h2"
    assert by_name["connect-ip"]["handshake-timeout"] == 30
    assert by_name["l4"]["network"] == "h3-l4proxy"
    assert by_name["future-network"]["network"] == "future-transport"


def test_masque_method_profiles_are_not_cross_converted_with_fake_credentials():
    surge = SurgeParser().parse_result(
        "masque = masque, masque.example.com, 443, username=user, password=pass"
    )
    to_mihomo = ClashEmitter().emit_result(surge.nodes)
    assert to_mihomo.supported_nodes == []
    assert to_mihomo.errors[0].code == "conversion.unsupported-protocol-variant"

    mihomo = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "masque",
                    "type": "masque",
                    "server": "masque.example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                    "ip": "172.16.0.2/32",
                }
            ]
        }
    )
    to_surge = SurgeEmitter().emit_result(mihomo.nodes)
    assert to_surge.supported_nodes == []
    assert to_surge.errors[0].code == "conversion.unsupported-protocol-variant"


def test_surge_builtin_aliases_round_trip_as_nodes():
    parsed = SurgeParser().parse_result(
        """
[Proxy]
On = direct, interface=en0
Off = reject
Drop = reject-drop
Stable = reject-no-drop
Gif = reject-tinygif
"""
    )

    assert parsed.issues == []
    assert isinstance(parsed.nodes[0], DirectNode)
    assert all(isinstance(node, RejectNode) for node in parsed.nodes[1:])
    assert [node.mode for node in parsed.nodes[1:]] == [
        RejectMode.REJECT,
        RejectMode.DROP,
        RejectMode.NO_DROP,
        RejectMode.TINYGIF,
    ]

    emission = SurgeEmitter().emit_result(parsed.nodes)

    assert emission.errors == []
    assert "On = direct, interface=en0" in emission.content
    assert "Off = reject" in emission.content
    assert "Drop = reject-drop" in emission.content
    assert "Stable = reject-no-drop" in emission.content
    assert "Gif = reject-tinygif" in emission.content

    to_mihomo = ClashEmitter().emit_result(parsed.nodes)
    assert [node.name for node in to_mihomo.supported_nodes] == ["On", "Off"]
    assert [proxy["type"] for proxy in to_mihomo.content["proxies"]] == [
        "direct",
        "reject",
    ]
    assert {issue.node for issue in to_mihomo.errors} == {
        "Drop",
        "Stable",
        "Gif",
    }

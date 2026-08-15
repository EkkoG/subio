from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import (
    NativeNode,
    DirectNode,
    Protocol,
    RejectNode,
    SSHNode,
    TailscaleNode,
    WireguardNode,
)
from subio_v2.parser.surge import SurgeParser
from subio_v2.surge.resources import (
    SurgeDocumentResources,
    SurgeNamedSection,
    get_surge_node_attachments,
)


def test_native_node_owns_surge_attachments_without_a_fake_endpoint():
    node = NativeNode(
        name="Tailnet",
        type=Protocol.TAILSCALE,
        native_format="surge",
    )
    attachments = get_surge_node_attachments(node)
    attachments.named_sections[("tailscale", "office")] = SurgeNamedSection(
        kind="Tailscale",
        name="office",
        lines=("auth-key = secret",),
    )

    assert node.server is None
    assert node.port is None
    assert get_surge_node_attachments(node) is attachments


def test_surge_common_tls_shadow_tls_and_unknown_parameters_round_trip():
    result = SurgeParser().parse_result(
        """
[Proxy]
proxy = https, example.com, 443, username=u, password=p, interface=en0, allow-other-interface=true, dns-follow-interface=false, no-error-alert=true, ip-version=prefer-v6, hybrid=auto, tfo=true, tos=0x20, ecn=on, block-quic=off, test-url=https://example.com/ping, test-timeout=5, test-udp=probe.example@198.51.100.1, sni=off, server-cert-verify-name=verify.example.com, server-cert-fingerprint-sha256=AA:BB, alpn="h2,http/1.1", client-cert=client, shadow-tls-password=shadow-secret, shadow-tls-sni=shadow.example.com, shadow-tls-version=3, future=one, future=two
[Keystore]
client = type = p12, base64 = Q0VSVA==, password = "p,12"
unused = type = p12, base64 = VU5VU0VE
"""
    )

    assert result.issues == []
    node = result.nodes[0]
    assert node.tls.sni_disabled is True
    assert node.tls.verify_name == "verify.example.com"
    assert node.tls.certificate_sha256 == "AA:BB"
    assert node.tls.client_cert_ref == "client"
    assert node.shadow_tls.password == "shadow-secret"
    assert node.shadow_tls.version == 3
    assert node.surge_options.allow_other_interface is True
    assert node.surge_options.dns_follow_interface is False
    assert node.surge_options.tos == "0x20"
    assert node.surge_options.test_udp == "probe.example@198.51.100.1"
    assert node.source_extensions["surge"]["parameters"] == [
        ("future", "one"),
        ("future", "two"),
    ]

    output = SurgeEmitter(resources=result.resources).emit(result.nodes)
    assert "sni=off" in output
    assert "server-cert-verify-name=verify.example.com" in output
    assert "server-cert-fingerprint-sha256=AA:BB" in output
    assert "client-cert=client" in output
    assert "shadow-tls-password=shadow-secret" in output
    assert "shadow-tls-version=3" in output
    assert "test-udp=probe.example@198.51.100.1" in output
    assert "future=one, future=two" in output
    assert 'password = "p,12"' in output
    assert "unused = type = p12, base64 = VU5VU0VE" in output


def test_surge_missing_client_certificate_is_an_emit_error():
    node = SurgeParser().parse(
        "[Proxy]\nproxy = https, example.com, 443, client-cert=missing"
    )[0]

    result = SurgeEmitter().emit_result([node])

    assert result.supported_nodes == []
    assert result.errors[0].field == "tls.client_cert_ref"


def test_surge_source_extensions_warn_on_cross_platform_emit():
    node = SurgeParser().parse(
        "[Proxy]\nproxy = http, example.com, 80, future=value, no-error-alert=true"
    )[0]

    result = ClashEmitter().emit_result([node])

    issue = next(
        issue
        for issue in result.issues
        if issue.code == "conversion.unconsumed-source-field"
    )
    assert issue.field == "source_extensions.surge"
    assert "future" in issue.message
    assert "no-error-alert" in issue.message


def test_sensitive_surge_values_are_hidden_from_repr():
    node = SSHNode(
        name="ssh",
        type=Protocol.SSH,
        server="example.com",
        port=22,
        username="root",
        password="password-secret",
        private_key="private-key-secret",
    )
    resources = SurgeDocumentResources(
        keystore={
            "key": {
                "type": "p12",
                "base64": "certificate-secret",
                "password": "keystore-secret",
            }
        }
    )

    assert "password-secret" not in repr(node)
    assert "private-key-secret" not in repr(node)
    assert "certificate-secret" not in repr(resources)
    assert "keystore-secret" not in repr(resources)


def test_surge_wireguard_multiple_peers_and_section_round_trip():
    content = """
[Proxy]
wg = wireguard, section-name=office, underlying-proxy=upstream

[WireGuard office]
private-key = private-secret
self-ip = 10.20.0.2
self-ip-v6 = fd00::2
dns-server = 10.20.0.1, fd00::1
prefer-ipv6 = true
mtu = 1280
peer = (public-key = peer-a, allowed-ips = "0.0.0.0/0, ::/0", endpoint = a.example.com:51820, preshared-key = shared-a, keepalive = 25)
peer = (public-key = peer-b, allowed-ips = 10.0.0.0/8, endpoint = b.example.com:51821, client-id = 83/12/235)
future-section-field = keep-me
"""

    result = SurgeParser().parse_result(content)

    assert result.issues == []
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert isinstance(node, WireguardNode)
    assert node.server == "a.example.com"
    assert node.port == 51820
    assert node.interface_ip == "10.20.0.2"
    assert node.interface_ipv6 == "fd00::2"
    assert node.dns_servers == ["10.20.0.1", "fd00::1"]
    assert node.peers and len(node.peers) == 2
    assert node.peers[1]["reserved"] == [83, 12, 235]
    assert node.dialer_proxy == "upstream"

    emission = SurgeEmitter(resources=result.resources).emit_result(result.nodes)

    assert emission.errors == []
    assert emission.emitted_policy_names == ["wg"]
    assert "wireguard:office" in emission.emitted_resource_keys
    assert (
        "wg = wireguard, section-name=office, underlying-proxy=upstream"
        in emission.content
    )
    assert "[WireGuard office]" in emission.content
    assert 'allowed-ips = "0.0.0.0/0, ::/0"' in emission.content
    assert "client-id = 83/12/235" in emission.content
    assert "future-section-field = keep-me" in emission.content

    reparsed = SurgeParser().parse_result("[Proxy]\n" + emission.content)
    assert reparsed.issues == []
    assert len(reparsed.nodes[0].peers) == 2


def test_surge_tailscale_and_builtin_aliases_are_nodes():
    result = SurgeParser().parse_result(
        """
[Proxy]
Tailnet = tailscale, section-name=office, test-timeout=8
On = direct, interface=en0
Off = reject-drop, no-error-alert=true

[Tailscale office]
auth-key = tskey-auth-example
hostname = surge-client
"""
    )

    assert len(result.nodes) == 3
    assert isinstance(result.nodes[0], TailscaleNode)
    assert isinstance(result.nodes[1], DirectNode)
    assert isinstance(result.nodes[2], RejectNode)
    assert result.nodes[0].hostname == "surge-client"
    assert result.nodes[0].auth_key == "tskey-auth-example"
    assert result.issues == []
    assert result.resources.policies == []
    assert ("tailscale", "office") not in result.resources.named_sections

    emission = SurgeEmitter(resources=result.resources).emit_result(result.nodes)

    assert emission.supported_nodes == result.nodes
    assert emission.emitted_policy_names == ["Tailnet", "On", "Off"]
    assert (
        "Tailnet = tailscale, section-name=office, test-timeout=8" in emission.content
    )
    assert "On = direct, interface=en0" in emission.content
    assert "Off = reject-drop, no-error-alert=true" in emission.content
    assert "[Tailscale office]" in emission.content
    assert "auth-key = tskey-auth-example" in emission.content


def test_clash_wireguard_defaults_are_made_explicit_for_surge():
    node = WireguardNode(
        name="wg",
        type=Protocol.WIREGUARD,
        server="2001:db8::1",
        port=51820,
        private_key="private",
        public_key="public",
        interface_ip="10.0.0.2",
        reserved="U4An",
    )

    emission = SurgeEmitter().emit_result([node])

    assert emission.errors == []
    assert 'allowed-ips = "0.0.0.0/0, ::/0"' in emission.content
    assert "endpoint = [2001:db8::1]:51820" in emission.content
    assert "client-id = U4An" in emission.content


def test_surge_tailscale_requires_exactly_one_login_method():
    result = SurgeParser().parse_result(
        """
[Proxy]
Tailnet = tailscale, section-name=office
[Tailscale office]
auth-key = tskey-auth-example
interactive-login = true
"""
    )

    assert result.nodes == []
    assert result.resources.policies == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "parse.resource"
    assert "exactly one" in result.issues[0].message


def test_surge_builtin_policy_names_cannot_be_redefined():
    result = SurgeParser().parse_result(
        """
[Proxy]
DIRECT = direct
REJECT = reject
"""
    )

    assert result.resources.policies == []
    assert [issue.code for issue in result.issues] == [
        "parse.ignored-built-in-redefinition",
        "parse.invalid-built-in-redefinition",
    ]

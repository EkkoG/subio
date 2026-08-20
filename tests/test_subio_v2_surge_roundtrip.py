from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.target import TargetValidationService as NodeConversionService
from subio_v2.core.nodes import HttpVariant


def test_surge_anytls_round_trip_with_reuse_and_tls():
    result = SurgeParser().parse_result(
        """
[Proxy]
any = anytls, example.com, 443, password=secret, reuse=false, sni=any.example.com, alpn="h2,http/1.1"
"""
    )

    assert result.issues == []
    node = result.nodes[0]
    assert node.reuse is False
    assert node.tls.enabled is True
    assert node.tls.server_name == "any.example.com"
    assert NodeConversionService("surge").check_node(node).supported

    output = SurgeEmitter().emit_result(result.nodes).content
    assert "any = anytls" in output
    assert "reuse=false" in output
    assert 'alpn="h2,http/1.1"' in output
    assert "udp-relay" not in output


def test_surge_h2_connect_round_trip_and_capability_boundary():
    node = SurgeParser().parse_result(
        """
[Proxy]
h2 = h2-connect, example.com, 443, username=u, password=p, headers="User-Agent:SubIO|X-Test:a=b", max-streams=8, udp-relay=true
"""
    ).nodes[0]

    assert node.variant == HttpVariant.H2_CONNECT
    assert node.tls.enabled is True
    assert node.headers == {"User-Agent": "SubIO", "X-Test": "a=b"}
    assert node.max_streams == 8
    assert node.udp is True
    assert NodeConversionService("surge").check_node(node).supported
    assert not NodeConversionService("clash-meta").check_node(node).supported

    output = SurgeEmitter().emit_result([node]).content
    assert "h2 = h2-connect" in output
    assert "headers=User-Agent:SubIO|X-Test:a=b" in output
    assert "max-streams=8" in output
    assert "udp-relay=true" in output


def test_surge_ssh_idle_timeout_and_fingerprints_round_trip():
    result = SurgeParser().parse_result(
        """
[Proxy]
ssh = ssh, example.com, 22, username=root, password=p, idle-timeout=60, server-fingerprint=SHA256:first, server-fingerprint="SHA256:second,SHA256:third"
"""
    )

    node = result.nodes[0]
    assert node.idle_timeout == 60
    assert node.server_fingerprints == [
        "SHA256:first",
        "SHA256:second",
        "SHA256:third",
    ]
    assert NodeConversionService("surge").check_node(node).supported

    output = SurgeEmitter().emit_result([node]).content
    assert "idle-timeout=60" in output
    assert output.count("server-fingerprint=") == 3


def test_surge_ssh_requires_authentication_material():
    node = SurgeParser().parse_result("[Proxy]\nssh = ssh, example.com, 22, username=root").nodes[0]

    result = NodeConversionService("surge").check_node(node)

    assert not result.supported
    assert "password" in {warning.field for warning in result.warnings}

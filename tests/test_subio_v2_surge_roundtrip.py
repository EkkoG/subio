from subio_v2.capabilities.checker import CapabilityChecker
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import HttpVariant
from subio_v2.parser.surge import SurgeParser


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
    assert CapabilityChecker("surge").check_node(node).supported

    output = SurgeEmitter().emit(result.nodes)
    assert "any = anytls" in output
    assert "reuse=false" in output
    assert 'alpn="h2,http/1.1"' in output
    assert "udp-relay" not in output


def test_surge_h2_connect_round_trip_and_capability_boundary():
    node = SurgeParser().parse(
        """
[Proxy]
h2 = h2-connect, example.com, 443, username=u, password=p, headers="User-Agent:SubIO|X-Test:a=b", max-streams=8, udp-relay=true
"""
    )[0]

    assert node.variant == HttpVariant.H2_CONNECT
    assert node.tls.enabled is True
    assert node.headers == {"User-Agent": "SubIO", "X-Test": "a=b"}
    assert node.max_streams == 8
    assert node.udp is True
    assert CapabilityChecker("surge").check_node(node).supported
    assert not CapabilityChecker("clash-meta").check_node(node).supported

    output = SurgeEmitter().emit([node])
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
    assert CapabilityChecker("surge").check_node(node).supported

    output = SurgeEmitter().emit([node])
    assert "idle-timeout=60" in output
    assert output.count("server-fingerprint=") == 3


def test_surge_ssh_requires_authentication_material():
    node = SurgeParser().parse("[Proxy]\nssh = ssh, example.com, 22, username=root")[0]

    result = CapabilityChecker("surge").check_node(node)

    assert not result.supported
    assert "password" in {warning.field for warning in result.warnings}

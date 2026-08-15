from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import Protocol, SSHNode
from subio_v2.parser.surge import SurgeParser
from subio_v2.surge.resources import SurgeDocumentResources


def test_surge_common_tls_shadow_tls_and_unknown_parameters_round_trip():
    result = SurgeParser().parse_result(
        """
[Proxy]
proxy = https, example.com, 443, username=u, password=p, interface=en0, allow-other-interface=true, dns-follow-interface=false, no-error-alert=true, ip-version=prefer-v6, hybrid=auto, tfo=true, tos=0x20, ecn=on, block-quic=off, test-url=https://example.com/ping, test-timeout=5, test-udp=true, sni=off, server-cert-verify-name=verify.example.com, server-cert-fingerprint-sha256=AA:BB, alpn="h2,http/1.1", client-cert=client, shadow-tls-password=shadow-secret, shadow-tls-sni=shadow.example.com, shadow-tls-version=3, future=one, future=two
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

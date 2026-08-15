from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.model.nodes import HttpNode, Protocol, SSHNode, TLSSettings
from subio_v2.parser.stash import StashParser


def test_stash_parser_normalizes_common_and_protocol_aliases():
    parsed = StashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "http",
                    "type": "http",
                    "server": "example.com",
                    "port": 443,
                    "tls": True,
                    "server-cert-fingerprint": "AA:BB",
                    "udp": False,
                    "tfo": True,
                    "dialer-proxy": "upstream",
                    "benchmark-url": "https://example.com/ping",
                },
                {
                    "name": "ssh",
                    "type": "ssh",
                    "server": "ssh.example.com",
                    "port": 22,
                    "user": "root",
                    "password": "secret",
                },
            ]
        }
    )

    assert parsed.issues == []
    http, ssh = parsed.nodes
    assert isinstance(http, HttpNode)
    assert http.tls.certificate_sha256 == "AA:BB"
    assert http.udp is False
    assert http.tfo is True
    assert http.dialer_proxy == "upstream"
    assert http.extra == {"benchmark-url": "https://example.com/ping"}
    assert http.extra_context.dialect == "stash"
    assert isinstance(ssh, SSHNode)
    assert ssh.username == "root"
    assert "user" not in ssh.extra


def test_internal_stash_emitter_preserves_stash_unknowns_and_field_names():
    node = StashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "http",
                    "type": "http",
                    "server": "example.com",
                    "port": 443,
                    "tls": True,
                    "server-cert-fingerprint": "AA:BB",
                    "benchmark-disabled": True,
                }
            ]
        }
    ).nodes[0]

    emission = StashEmitter().emit_result([node])

    assert emission.errors == []
    proxy = emission.content["proxies"][0]
    assert proxy["server-cert-fingerprint"] == "AA:BB"
    assert "fingerprint" not in proxy
    assert proxy["benchmark-disabled"] is True


def test_stash_unknowns_do_not_leak_to_mihomo_but_shared_tls_does():
    node = StashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "http",
                    "type": "http",
                    "server": "example.com",
                    "port": 443,
                    "tls": True,
                    "server-cert-fingerprint": "AA:BB",
                    "benchmark-disabled": True,
                }
            ]
        }
    ).nodes[0]

    emission = ClashEmitter("clash-meta").emit_result([node])

    proxy = emission.content["proxies"][0]
    assert proxy["fingerprint"] == "AA:BB"
    assert "benchmark-disabled" not in proxy
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        and "benchmark-disabled" in issue.message
        for issue in emission.issues
    )


def test_internal_stash_emitter_crops_unsupported_shared_common_fields():
    node = HttpNode(
        name="http",
        type=Protocol.HTTP,
        server="example.com",
        port=443,
        tls=TLSSettings(
            enabled=True,
            certificate_sha256="AA:BB",
            verify_name="verify.example.com",
            certificate="client certificate",
        ),
        routing_mark=100,
    )

    emission = StashEmitter().emit_result([node])

    proxy = emission.content["proxies"][0]
    assert proxy["server-cert-fingerprint"] == "AA:BB"
    assert "name-cert-verify" not in proxy
    assert "certificate" not in proxy
    assert "routing-mark" not in proxy
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        and "routing-mark" in issue.message
        for issue in emission.issues
    )

from pathlib import Path

from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.parser.surge import SurgeParser


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "surge" / "official"


def test_official_basic_proxy_fixture_is_parseable():
    content = (FIXTURE_DIR / "basic.conf").read_text()

    result = SurgeParser().parse_result(content)

    assert result.issues == []
    assert [node.name for node in result.nodes] == [
        "http",
        "https",
        "socks",
        "ss",
        "vmess",
        "trojan",
        "snell",
        "tuic",
        "hysteria2",
        "ssh",
    ]
    output = SurgeEmitter().emit(result.nodes)
    assert "test-udp=probe.example@198.51.100.1" in output
    assert len(SurgeParser().parse(output)) == 10


def test_official_quoted_alpn_regression_baseline():
    node = SurgeParser().parse(
        '[Proxy]\ntuic = tuic-v5, example.com, 443, uuid=u, password=p, alpn="h3,h2"'
    )[0]

    assert node.tls.alpn == ["h3", "h2"]


def test_official_udp_and_hysteria2_regression_baseline():
    content = """
[Proxy]
http = http, example.com, 80
hysteria2 = hysteria2, example.com, 443, password=p, gecko-password=secret
"""
    nodes = SurgeParser().parse(content)
    output = SurgeEmitter().emit(nodes)

    http_line = next(line for line in output.splitlines() if line.startswith("http ="))
    assert "udp-relay" not in http_line
    assert "gecko-password=secret" in output


def test_official_node_attachment_fixture_is_parseable():
    content = (FIXTURE_DIR / "document-resources.conf").read_text()

    result = SurgeParser().parse_result(content)

    assert result.issues == []
    assert [node.name for node in result.nodes] == [
        "Office WG",
        "My Tailnet",
        "On",
        "Off",
    ]
    assert result.resources == {}


def test_official_opaque_and_external_fixtures_follow_security_boundary():
    opaque = SurgeParser(source_kind="remote").parse_result(
        (FIXTURE_DIR / "opaque.conf").read_text()
    )
    rejected = SurgeParser(source_kind="remote").parse_result(
        (FIXTURE_DIR / "external.conf").read_text()
    )
    allowed = SurgeParser(source_kind="local").parse_result(
        (FIXTURE_DIR / "external.conf").read_text()
    )

    assert opaque.issues == []
    assert [node.type.value for node in opaque.nodes] == ["masque", "trusttunnel"]
    assert opaque.resources == {}
    assert rejected.resources == {}
    assert rejected.issues[0].code == "security.remote-external-blocked"
    assert rejected.issues[0].severity.value == "warning"
    assert len(allowed.nodes) == 1
    assert allowed.resources == {}

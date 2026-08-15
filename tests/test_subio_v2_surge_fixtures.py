from pathlib import Path

import pytest

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
    assert len(SurgeParser().parse(SurgeEmitter().emit(result.nodes))) == 10


@pytest.mark.xfail(reason="fixed by the Surge syntax phase", strict=False)
def test_official_quoted_alpn_regression_baseline():
    node = SurgeParser().parse(
        '[Proxy]\ntuic = tuic-v5, example.com, 443, uuid=u, password=p, alpn="h3,h2"'
    )[0]

    assert node.tls.alpn == ["h3", "h2"]


@pytest.mark.xfail(reason="fixed by the Surge capability phase", strict=False)
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

from subio_v2.parser.clash import ClashParser
from subio_v2.parser.factory import ParserFactory
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.v2rayn import V2RayNParser


def test_parser_factory_returns_fresh_mapped_instances():
    clash = ParserFactory.get_parser("clash")
    clash_meta = ParserFactory.get_parser("clash-meta")
    v2 = ParserFactory.get_parser("v2rayn")
    surge = ParserFactory.get_parser("surge")
    subio = ParserFactory.get_parser("subio")

    assert isinstance(clash, ClashParser)
    assert isinstance(clash_meta, ClashParser)
    assert clash_meta is not clash
    assert ParserFactory.get_parser("clash") is not clash
    assert isinstance(v2, V2RayNParser)
    assert isinstance(surge, SurgeParser)
    assert isinstance(subio, SubioParser)
    assert ParserFactory.get_parser("unknown") is None


def test_surge_parsers_from_factory_keep_keystores_isolated():
    provider_a = """
[Proxy]
a = ssh, a.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLUE=
"""
    provider_b = """
[Proxy]
b = ssh, b.example.com, 22, username=root, private-key=shared
[Keystore]
shared = type = openssh-private-key, base64 = S0VZLUI=
"""

    parser_a = ParserFactory.get_parser("surge")
    parser_b = ParserFactory.get_parser("surge")
    assert isinstance(parser_a, SurgeParser)
    assert isinstance(parser_b, SurgeParser)

    parser_a.parse(provider_a)
    parser_b.parse(provider_b)

    assert parser_a.keystore["shared"]["base64"] == "S0VZLUE="
    assert parser_b.keystore["shared"]["base64"] == "S0VZLUI="

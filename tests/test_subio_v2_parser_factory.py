from subio_v2.parser.clash import ClashParser
from subio_v2.parser.factory import ParserFactory
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.stash import StashParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.surge.resources import get_surge_node_attachments


def test_parser_factory_returns_fresh_mapped_instances():
    clash = ParserFactory.get_parser("clash")
    clash_meta = ParserFactory.get_parser("clash-meta")
    stash = ParserFactory.get_parser("stash")
    v2 = ParserFactory.get_parser("v2rayn")
    surge = ParserFactory.get_parser("surge")
    subio = ParserFactory.get_parser("subio")

    assert isinstance(clash, ClashParser)
    assert isinstance(clash_meta, ClashParser)
    assert clash_meta is not clash
    assert isinstance(stash, StashParser)
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

    nodes_a = parser_a.parse(provider_a)
    nodes_b = parser_b.parse(provider_b)

    entry_a = get_surge_node_attachments(nodes_a[0]).keystore["shared"]
    entry_b = get_surge_node_attachments(nodes_b[0]).keystore["shared"]

    assert entry_a.values["base64"] == "S0VZLUE="
    assert entry_b.values["base64"] == "S0VZLUI="
    assert entry_a is not entry_b

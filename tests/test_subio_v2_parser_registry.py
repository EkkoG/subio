from subio_v2.adapters.catalog import get_parser
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.surge.resources import get_surge_node_attachments


def test_parser_registry_returns_fresh_mapped_instances():
    clash = get_parser("clash")
    mihomo = get_parser("mihomo")
    clash_meta = get_parser("clash-meta")
    stash = get_parser("stash")
    v2 = get_parser("v2rayn")
    surge = get_parser("surge")
    subio = get_parser("subio")

    assert isinstance(clash, ClashParser)
    assert isinstance(mihomo, ClashParser)
    assert isinstance(clash_meta, ClashParser)
    assert mihomo.context.dialect == clash_meta.context.dialect == "mihomo"
    assert len({id(clash), id(mihomo), id(clash_meta)}) == 3
    assert isinstance(stash, StashParser)
    assert get_parser("clash") is not clash
    assert isinstance(v2, V2RayNParser)
    assert isinstance(surge, SurgeParser)
    assert isinstance(subio, SubioParser)
    assert get_parser("unknown") is None


def test_surge_parsers_from_registry_keep_keystores_isolated():
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

    parser_a = get_parser("surge")
    parser_b = get_parser("surge")
    assert isinstance(parser_a, SurgeParser)
    assert isinstance(parser_b, SurgeParser)

    nodes_a = parser_a.parse_result(provider_a).nodes
    nodes_b = parser_b.parse_result(provider_b).nodes

    entry_a = get_surge_node_attachments(nodes_a[0]).keystore["shared"]
    entry_b = get_surge_node_attachments(nodes_b[0]).keystore["shared"]

    assert entry_a.values["base64"] == "S0VZLUE="
    assert entry_b.values["base64"] == "S0VZLUI="
    assert entry_a is not entry_b


def test_surge_registry_owns_source_trust_options():
    parser = get_parser(
        "surge", source_kind="remote", allow_unsafe_external=True
    )

    assert isinstance(parser, SurgeParser)
    assert parser.source_kind == "remote"
    assert parser.allow_unsafe_external is True

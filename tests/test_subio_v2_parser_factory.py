from subio_v2.parser.factory import ParserFactory


def test_parser_factory_mappings_singletons():
    # First retrieval initializes parsers
    clash = ParserFactory.get_parser("clash")
    assert clash is not None
    # clash-meta should return same instance
    clash_meta = ParserFactory.get_parser("clash-meta")
    assert clash_meta is clash

    v2 = ParserFactory.get_parser("v2rayn")
    assert v2 is not None

    surge = ParserFactory.get_parser("surge")
    assert surge is not None

    subio = ParserFactory.get_parser("subio")
    assert subio is not None

    # Unknown returns None
    assert ParserFactory.get_parser("unknown") is None

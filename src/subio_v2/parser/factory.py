from typing import Dict
from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.subio import SubioParser


class ParserFactory:
    _parsers: Dict[str, BaseParser] = {}

    @classmethod
    def get_parser(cls, parser_type: str) -> BaseParser | None:
        if not cls._parsers:
            cls._initialize_parsers()
        return cls._parsers.get(parser_type)

    @classmethod
    def _initialize_parsers(cls):
        # Initialize all parsers once
        clash = ClashParser()
        v2rayn = V2RayNParser()
        surge = SurgeParser()
        subio = SubioParser()

        # Register mappings
        cls._parsers["clash"] = clash
        cls._parsers["clash-meta"] = clash
        cls._parsers["v2rayn"] = v2rayn
        cls._parsers["surge"] = surge
        cls._parsers["subio"] = subio

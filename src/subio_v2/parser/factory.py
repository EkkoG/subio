from typing import Callable, Dict

from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.dialect import DialectContext


class ParserFactory:
    _factories: Dict[str, Callable[[], BaseParser]] = {
        "clash": lambda: ClashParser(DialectContext("clash", "yaml")),
        "clash-meta": lambda: ClashParser(DialectContext("mihomo", "yaml")),
        "v2rayn": V2RayNParser,
        "surge": SurgeParser,
        "subio": SubioParser,
    }

    @classmethod
    def get_parser(cls, parser_type: str) -> BaseParser | None:
        factory = cls._factories.get(parser_type)
        return factory() if factory else None

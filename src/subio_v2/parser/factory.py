from typing import Callable, Dict

from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.stash import StashParser
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.dialect import DialectContext
from subio_v2.platforms import normalize_platform


class ParserFactory:
    _factories: Dict[str, Callable[[], BaseParser]] = {
        "clash": lambda: ClashParser(DialectContext("clash", "yaml")),
        "mihomo": lambda: ClashParser(DialectContext("mihomo", "yaml")),
        "stash": StashParser,
        "v2rayn": V2RayNParser,
        "surge": SurgeParser,
        "subio": SubioParser,
    }

    @classmethod
    def get_parser(cls, parser_type: str) -> BaseParser | None:
        factory = cls._factories.get(normalize_platform(parser_type))
        return factory() if factory else None

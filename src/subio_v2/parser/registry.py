from collections.abc import Callable
from types import MappingProxyType

from subio_v2.dialect import DialectContext
from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser
from subio_v2.parser.subio import SubioParser
from subio_v2.parser.surge import SurgeParser
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.platforms import normalize_platform

_CONSTRUCTORS = MappingProxyType(
    {
        "clash": lambda: ClashParser(DialectContext("clash", "yaml")),
        "mihomo": lambda: ClashParser(DialectContext("mihomo", "yaml")),
        "stash": StashParser,
        "v2rayn": V2RayNParser,
        "subio": SubioParser,
    }
)


def get_parser(
    parser_type: str,
    *,
    source_kind: str = "unknown",
    allow_unsafe_external: bool = False,
) -> BaseParser | None:
    parser_type = normalize_platform(parser_type)
    if parser_type == "surge":
        return SurgeParser(
            source_kind=source_kind,
            allow_unsafe_external=allow_unsafe_external,
        )
    constructor: Callable[[], BaseParser] | None = _CONSTRUCTORS.get(parser_type)
    return constructor() if constructor else None

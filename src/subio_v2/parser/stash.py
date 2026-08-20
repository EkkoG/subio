from subio_v2.core.dialect import DialectContext
from subio_v2.parser.clash import ClashParser


class StashParser(ClashParser):
    """Internal Stash YAML parser exposed through the parser registry."""

    def __init__(self):
        super().__init__(DialectContext("stash", "yaml"))

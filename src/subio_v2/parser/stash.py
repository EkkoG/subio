from subio_v2.dialect import DialectContext
from subio_v2.parser.clash import ClashParser


class StashParser(ClashParser):
    """Internal Stash YAML parser; exposed through ParserFactory in stage 9."""

    def __init__(self):
        super().__init__(DialectContext("stash", "yaml"))

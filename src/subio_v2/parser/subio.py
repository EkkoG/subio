import json
import sys
from typing import Any, List

import json5
import toml
import yaml

from subio_v2.conversion import ParseResult
from subio_v2.model.nodes import Node
from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.utils.logger import logger


class SubioParser(BaseParser):
    """
    Subio 格式解析器

    支持的格式（按优先级）：
    1. TOML
    2. JSON
    3. JSON5 (支持注释、尾逗号等)
    4. YAML
    """

    def __init__(self):
        self.clash_parser = ClashParser()

    def parse(self, content: Any) -> List[Node]:
        try:
            return self.parse_result(content).nodes
        except ValueError as exc:
            logger.error(str(exc))
            sys.exit(1)

    def parse_result(self, content: Any) -> ParseResult:
        if not isinstance(content, str):
            raise ValueError("Invalid content type for SubioParser")

        data = None

        # Try TOML first
        try:
            data = toml.loads(content)
        except Exception:
            pass

        # Try JSON
        if data is None:
            try:
                data = json.loads(content)
            except Exception:
                pass

        # Try JSON5 (supports comments, trailing commas, etc.)
        if data is None:
            try:
                data = json5.loads(content)
            except Exception:
                pass

        # Try YAML
        if data is None:
            try:
                data = yaml.safe_load(content)
            except Exception:
                pass

        if data is None:
            raise ValueError(
                "Error parsing subio provider: Unknown format "
                "(tried toml, json, json5, yaml)"
            )

        if isinstance(data, dict) and "proxies" in data:
            return self.clash_parser.parse_result({"proxies": data["proxies"]})
        raise ValueError("Error: subio provider does not contain 'proxies' list.")

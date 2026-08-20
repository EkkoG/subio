import json
from typing import Any

import json5
import toml
import yaml

from subio_v2.conversion import ParseResult
from subio_v2.subio_format.codec import SubioNodeCodec


class SubioParser:
    """
    Subio 格式解析器

    支持的格式（按优先级）：
    1. TOML
    2. JSON
    3. JSON5 (支持注释、尾逗号等)
    4. YAML
    """

    def __init__(self):
        self.node_codec = SubioNodeCodec()

    def parse_result(self, content: Any) -> ParseResult:
        if not isinstance(content, str):
            raise ValueError("Invalid content type for SubioParser")

        data = None
        source_format = None

        # Try TOML first
        try:
            data = toml.loads(content)
            source_format = "toml"
        except Exception:
            pass

        # Try JSON
        if data is None:
            try:
                data = json.loads(content)
                source_format = "json"
            except Exception:
                pass

        # Try JSON5 (supports comments, trailing commas, etc.)
        if data is None:
            try:
                data = json5.loads(content)
                source_format = "json5"
            except Exception:
                pass

        # Try YAML
        if data is None:
            try:
                data = yaml.safe_load(content)
                source_format = "yaml"
            except Exception:
                pass

        if data is None:
            raise ValueError(
                "Error parsing subio provider: Unknown format "
                "(tried toml, json, json5, yaml)"
            )

        if (
            isinstance(data, dict)
            and "proxies" in data
            and ("version" in data or "nodes" in data)
        ):
            return self.node_codec.decode_document(data, source_format or "unknown")
        if isinstance(data, dict) and "proxies" in data:
            return self.node_codec.fatal_result(
                "parse.subio.legacy-format-removed",
                "Legacy SubIO 'proxies' syntax is no longer supported",
                field="proxies",
            )
        return self.node_codec.decode_document(data, source_format or "unknown")

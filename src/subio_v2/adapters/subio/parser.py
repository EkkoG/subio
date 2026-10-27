import json
from collections.abc import Mapping
from typing import Any

import json5
import toml
import yaml

from subio_v2.adapters.subio.codec import SubioNodeCodec
from subio_v2.core.parameters import ParameterValue, bind_document_parameters
from subio_v2.core.results import ParseResult


class SubioParser:
    """
    Subio 格式解析器

    支持的格式（按优先级）：
    1. TOML
    2. JSON
    3. JSON5 (支持注释、尾逗号等)
    4. YAML
    """

    def __init__(self, *, parameters: Mapping[str, ParameterValue] | None = None):
        self.node_codec = SubioNodeCodec()
        self.parameters = dict(parameters) if parameters is not None else None

    def parse_result(self, content: Any) -> ParseResult:
        return self.parse_document(self.decode_source(content))

    @staticmethod
    def decode_source(content: Any) -> tuple[Any, str]:
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
        return data, source_format

    def parse_document(self, document: tuple[Any, str]) -> ParseResult:
        data, source_format = document
        if self.parameters is not None:
            data = bind_document_parameters(data, "nodes", self.parameters)

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

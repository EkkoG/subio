import toml
import json
import json5
import yaml
import sys
from typing import Any, List
from subio_v2.parser.base import BaseParser
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Node
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
        if not isinstance(content, str):
            logger.error("Invalid content type for SubioParser")
            sys.exit(1)

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
            logger.error("Error parsing subio provider: Unknown format (tried toml, json, json5, yaml)")
            sys.exit(1)

        if isinstance(data, dict) and "proxies" in data:
            return self.clash_parser.parse({"proxies": data["proxies"]})
        else:
            logger.error("Error: subio provider does not contain 'proxies' list.")
            sys.exit(1)

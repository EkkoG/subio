import sys
from typing import Any, Dict, List

import yaml

import subio_v2.protocols as protocol_registry
from subio_v2.parser.base import BaseParser
from subio_v2.utils.logger import logger


class ClashParser(BaseParser):
    def parse(self, content: Any) -> List:
        if isinstance(content, str):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"YAML parse error: {e}")
                sys.exit(1)
        elif isinstance(content, dict):
            data = content
        else:
            logger.error("Invalid content type for ClashParser")
            sys.exit(1)

        if not isinstance(data, dict):
            logger.error(
                f"Invalid Clash config format: Expected dict, got {type(data)}. "
                f"Content preview: {str(content)[:100]}"
            )
            sys.exit(1)

        proxies = data.get("proxies")
        if proxies is None:
            logger.error("Clash config missing 'proxies' key")
            sys.exit(1)
        if not isinstance(proxies, list):
            logger.error("'proxies' is not a list")
            sys.exit(1)

        nodes = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            node = self._parse_node(proxy)
            if node:
                nodes.append(node)
        return nodes

    def _parse_node(self, data: Dict[str, Any]):
        node_type = data.get("type")
        if not node_type:
            return None

        desc = protocol_registry.by_clash_type(node_type)
        if not desc:
            logger.warning(f"Unsupported Clash proxy type: {node_type}")
            return None
        try:
            return desc.parse_clash(data)
        except Exception as e:
            logger.warning(f"Error parsing node {data.get('name')}: {e}")
            return None

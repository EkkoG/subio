from typing import Any, Dict, List

import subio_v2.protocols as protocol_registry
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import Node
from subio_v2.utils.logger import logger


class ClashEmitter(BaseEmitter):
    platform = "clash-meta"

    def __init__(self, platform: str = "clash-meta"):
        self.platform = platform
        super().__init__()

    def emit(self, nodes: List[Node]) -> Dict[str, Any]:
        supported_nodes, _ = self.emit_with_check(nodes)
        proxies = []
        for node in supported_nodes:
            proxy = self._emit_node(node)
            if proxy:
                proxies.append(proxy)
        return {"proxies": proxies}

    def _emit_node(self, node: Node) -> Dict[str, Any] | None:
        desc = protocol_registry.get(node.type)
        if not desc:
            return None
        try:
            return desc.emit_clash(node)
        except Exception as e:
            logger.warning(f"Error emitting node '{node.name}' via registry: {e}")
            return None

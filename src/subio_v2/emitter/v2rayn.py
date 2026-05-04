import base64
from typing import List
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter import link
from subio_v2.model.nodes import Node


class V2RayNEmitter(BaseEmitter):
    platform = "v2rayn"

    def emit(self, nodes: List[Node]) -> str:
        supported_nodes, _ = self.emit_with_check(nodes)

        lines = []
        for node in supported_nodes:
            line = self._emit_node(node)
            if line:
                lines.append(line)

        # V2RayN subscription is base64 of joined lines
        return base64.b64encode("\n".join(lines).encode("utf-8")).decode("utf-8")

    def emit_list(self, nodes: List[Node]) -> str:
        """Return plain list of links (for debugging or other formats)"""
        supported_nodes, _ = self.emit_with_check(nodes)

        lines = []
        for node in supported_nodes:
            line = self._emit_node(node)
            if line:
                lines.append(line)
        return "\n".join(lines)

    def _emit_node(self, node: Node) -> str | None:
        return link.build_url(node)

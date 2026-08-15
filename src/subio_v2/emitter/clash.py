from typing import Any, Dict, List

import subio_v2.protocols as protocol_registry
from subio_v2.conversion import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import Node


class ClashEmitter(BaseEmitter):
    platform = "clash-meta"

    def __init__(self, platform: str = "clash-meta"):
        self.platform = platform
        super().__init__()

    def emit(self, nodes: List[Node]) -> Dict[str, Any]:
        result = self.emit_result(nodes)
        self.log_issues(result.issues)
        return result.content

    def emit_result(self, nodes: List[Node]) -> EmissionResult[Dict[str, Any]]:
        checked_nodes, issues = self.emit_with_check(nodes)
        emitted_nodes: list[Node] = []
        proxies: list[Dict[str, Any]] = []
        for node in checked_nodes:
            try:
                proxy = self._emit_node(node)
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Failed to emit Clash proxy: {exc}",
                    )
                )
                continue
            if proxy is None:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        "No Clash emitter is registered for this protocol",
                        field="type",
                    )
                )
                continue
            proxies.append(proxy)
            emitted_nodes.append(node)
        return EmissionResult(
            content={"proxies": proxies},
            supported_nodes=emitted_nodes,
            issues=issues,
        )

    def _emit_node(self, node: Node) -> Dict[str, Any] | None:
        desc = protocol_registry.get(node.type)
        if not desc:
            return None
        return desc.emit_clash(node)

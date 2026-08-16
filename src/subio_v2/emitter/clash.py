from typing import Any, Dict, List

import subio_v2.protocols as protocol_registry
from subio_v2.clash.dialect import post_descriptor_emit
from subio_v2.conversion import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import Node


class ClashEmitter(BaseEmitter):
    platform = "mihomo"

    def __init__(self, platform: str = "mihomo"):
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
                proxy, dropped_fields = self._emit_node(node)
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
            if dropped_fields:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.WARNING,
                        "Source fields cannot be represented by this target: "
                        + ", ".join(dropped_fields),
                        field="node",
                        stage="conversion",
                        code="conversion.unconsumed-source-field",
                    )
                )
        return EmissionResult(
            content={"proxies": proxies},
            supported_nodes=emitted_nodes,
            issues=issues,
            extras={"template_context": self.template_context(emitted_nodes)},
        )

    def _emit_node(
        self, node: Node
    ) -> tuple[Dict[str, Any] | None, tuple[str, ...]]:
        desc = protocol_registry.get(node.type)
        if not desc or not desc.supports_dialect(self.target_context.dialect):
            return None, ()
        proxy = desc.emit_clash(node, self.target_context)
        return self._post_descriptor_emit(proxy, node)

    def _post_descriptor_emit(
        self, proxy: Dict[str, Any], node: Node
    ) -> tuple[Dict[str, Any], tuple[str, ...]]:
        return post_descriptor_emit(proxy, node, self.target_context, self.platform)

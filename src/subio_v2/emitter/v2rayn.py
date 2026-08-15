import base64
from typing import List
from subio_v2.conversion import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter import link
from subio_v2.model.nodes import Node


class V2RayNEmitter(BaseEmitter):
    platform = "v2rayn"

    def emit(self, nodes: List[Node]) -> str:
        result = self.emit_result(nodes)
        self.log_issues(result.issues)
        return result.content

    def emit_result(self, nodes: List[Node]) -> EmissionResult[str]:
        checked_nodes, issues = self.emit_with_check(nodes)

        lines: list[str] = []
        emitted_nodes: list[Node] = []
        for node in checked_nodes:
            try:
                line = self._emit_node(node)
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Failed to build v2rayN link: {exc}",
                    )
                )
                continue
            if line is None:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        "No representable v2rayN link is available for this node",
                    )
                )
                continue
            lines.append(line)
            emitted_nodes.append(node)

        # V2RayN subscription is base64 of joined lines
        plain = "\n".join(lines)
        content = base64.b64encode(plain.encode("utf-8")).decode("utf-8")
        return EmissionResult(
            content=content,
            supported_nodes=emitted_nodes,
            issues=issues,
            extras={
                "list": plain,
                "template_context": self.template_context(emitted_nodes),
            },
        )

    def emit_list(self, nodes: List[Node]) -> str:
        """Return plain list of links (for debugging or other formats)"""
        result = self.emit_result(nodes)
        self.log_issues(result.issues)
        return result.extras["list"]

    def _emit_node(self, node: Node) -> str | None:
        return link.build_url(node)

"""
dae emitter

输出 dae `node { ... }` 块所需的 `'name': 'link'` 列表，以及
dae 订阅文件所需的纯文本 URL 列表（每行一条）。

dae dialer chain 支持：当节点的 `dialer_proxy` 指向同一 emit 列表中
的另一节点时，输出 `'name': 'link -> dialer_link'`；否则降级为单节点
链接并发出 warning。
"""

from typing import Dict, List
from subio_v2.conversion import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter import link
from subio_v2.model.nodes import Node


class DaeEmitter(BaseEmitter):
    platform = "dae"

    def emit_result(self, nodes: List[Node]) -> EmissionResult[str]:
        checked_nodes, issues = self.emit_with_check(nodes)
        node_by_name: Dict[str, Node] = {}
        url_by_id: Dict[int, str] = {}
        candidate_nodes: list[Node] = []

        for node in checked_nodes:
            if node.name in node_by_name:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Duplicate node name in dae artifact: {node.name}",
                        field="name",
                    )
                )
                continue
            try:
                url = link.build_url(node)
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Unable to build dae link: {exc}",
                    )
                )
                continue
            if not url:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        "Unable to build dae link for this protocol",
                    )
                )
                continue
            node_by_name[node.name] = node
            url_by_id[id(node)] = url
            candidate_nodes.append(node)

        lines: list[str] = []
        subscription_lines: list[str] = []
        emitted_nodes: list[Node] = []
        for node in candidate_nodes:
            try:
                chain_url = self._build_chain_url(
                    node, node_by_name, url_by_id, visiting=set()
                )
            except Exception as exc:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        str(exc),
                        field="dialer_proxy",
                    )
                )
                continue
            lines.append(f"'{node.name}': '{chain_url}'")
            subscription_lines.append(chain_url)
            emitted_nodes.append(node)

        subscription = "\n".join(subscription_lines)
        return EmissionResult(
            content="\n".join(lines),
            supported_nodes=emitted_nodes,
            issues=issues,
            extras={
                "subscription": subscription,
                "template_context": {
                    "proxies_names": ", ".join(
                        f"'{node.name}'" for node in emitted_nodes
                    ),
                    "subscription": subscription,
                },
            },
        )

    def emit_subscription(self, nodes: List[Node]) -> str:
        """纯文本订阅：每行一条 URL（不做 base64）。"""
        result = self.emit_result(nodes)
        self._raise_legacy_emit_error(result)
        self.log_issues(result.issues)
        return result.extras["subscription"]

    def _raise_legacy_emit_error(self, result: EmissionResult[str]) -> None:
        emit_errors = [issue for issue in result.errors if issue.stage == "emit"]
        if emit_errors:
            raise ValueError(emit_errors[0].message)

    @staticmethod
    def _build_indexes(
        nodes: List[Node],
    ) -> tuple[Dict[str, Node], Dict[int, str]]:
        node_by_name: Dict[str, Node] = {}
        url_by_id: Dict[int, str] = {}
        for node in nodes:
            if node.name in node_by_name:
                raise ValueError(f"Duplicate node name in dae artifact: {node.name}")
            url = link.build_url(node)
            if not url:
                raise ValueError(
                    f"Unable to build dae link for node '{node.name}' ({node.type.value})"
                )
            node_by_name[node.name] = node
            url_by_id[id(node)] = url
        return node_by_name, url_by_id

    def _build_chain_url(
        self,
        node: Node,
        node_by_name: Dict[str, Node],
        url_by_id: Dict[int, str],
        visiting: set[str],
    ) -> str:
        """Resolve the complete dialer chain and reject missing targets or cycles."""
        if node.name in visiting:
            cycle = " -> ".join([*visiting, node.name])
            raise ValueError(f"Cyclic dae dialer chain: {cycle}")

        url = url_by_id[id(node)]
        dialer_name = getattr(node, "dialer_proxy", None)
        if not dialer_name:
            return url

        dialer_node = node_by_name.get(dialer_name)
        if dialer_node is None:
            raise ValueError(
                f"Node '{node.name}' references unknown dialer_proxy '{dialer_name}'"
            )

        visiting.add(node.name)
        try:
            dialer_url = self._build_chain_url(
                dialer_node, node_by_name, url_by_id, visiting
            )
        finally:
            visiting.remove(node.name)
        return f"{url} -> {dialer_url}"

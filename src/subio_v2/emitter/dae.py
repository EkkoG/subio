"""
dae emitter

输出 dae `node { ... }` 块所需的 `'name': 'link'` 列表，以及
dae 订阅文件所需的纯文本 URL 列表（每行一条）。

dae dialer chain 支持：当节点的 `dialer_proxy` 指向同一 emit 列表中
的另一节点时，输出 `'name': 'link -> dialer_link'`；否则降级为单节点
链接并发出 warning。
"""


from subio_v2 import links as link
from subio_v2.core.results import EmissionResult, IssueSeverity
from subio_v2.emitter.base import BaseEmitter
from subio_v2.core.nodes import Node


class DaeEmitter(BaseEmitter):
    platform = "dae"

    def emit_result(self, nodes: list[Node]) -> EmissionResult[str]:
        issues = []
        node_by_name: dict[str, Node] = {}
        url_by_id: dict[int, str] = {}
        candidate_nodes: list[Node] = []

        for node in nodes:
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
            encoded = self.encode_node(
                node, lambda item: link.build_url(item, target=self.platform)
            )
            issues.extend(encoded.issues)
            if encoded.supported_node is None:
                continue
            url = encoded.content
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

    def emit_subscription(self, nodes: list[Node]) -> str:
        """纯文本订阅：每行一条 URL（不做 base64）。"""
        result = self.emit_result(nodes)
        emit_errors = [issue for issue in result.errors if issue.stage == "emit"]
        if emit_errors:
            raise ValueError(emit_errors[0].message)
        self.log_issues(result.issues)
        return result.extras["subscription"]

    @staticmethod
    def _build_indexes(
        nodes: list[Node],
    ) -> tuple[dict[str, Node], dict[int, str]]:
        node_by_name: dict[str, Node] = {}
        url_by_id: dict[int, str] = {}
        for node in nodes:
            if node.name in node_by_name:
                raise ValueError(f"Duplicate node name in dae artifact: {node.name}")
            url = link.build_url(node, target="dae")
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
        node_by_name: dict[str, Node],
        url_by_id: dict[int, str],
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

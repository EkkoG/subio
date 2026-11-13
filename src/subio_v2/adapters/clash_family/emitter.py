import copy
from typing import Any, Dict, List

from subio_v2.adapters.base import BaseEmitter
from subio_v2.core.nodes import Node, SourcePassthroughNode
from subio_v2.core.results import EmissionResult, IssueSeverity


class ClashEmitter(BaseEmitter):
    platform = "mihomo"

    def __init__(self, platform: str = "mihomo"):
        self.platform = platform
        super().__init__()

    def emit_result(self, nodes: List[Node]) -> EmissionResult[Dict[str, Any]]:
        issues = []
        emitted_nodes: list[Node] = []
        proxies: list[Dict[str, Any]] = []
        for node in nodes:
            encoded = self.encode_node(node)
            issues.extend(encoded.issues)
            if encoded.supported_node is None:
                continue
            proxy, dropped_fields = encoded.content
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
        retained, relation_issues = self.retain_dialer_indices(nodes, emitted_nodes)
        issues.extend(relation_issues)
        return EmissionResult(
            content={
                "proxies": [
                    proxy for index, proxy in enumerate(proxies) if index in retained
                ]
            },
            supported_nodes=[
                node for index, node in enumerate(emitted_nodes) if index in retained
            ],
            issues=issues,
        )

    @staticmethod
    def _emit_source_passthrough(
        node: SourcePassthroughNode,
    ) -> Dict[str, Any]:
        if not isinstance(node.raw, dict):
            raise ValueError("Source passthrough node does not contain a YAML proxy")

        output = copy.deepcopy(node.raw)
        output["name"] = node.name
        for attr, key, default in (
            ("server", "server", None),
            ("port", "port", None),
            ("udp", "udp", True),
            ("ip_version", "ip-version", None),
            ("tfo", "tfo", False),
            ("mptcp", "mptcp", False),
            ("dialer_proxy", "dialer-proxy", None),
            ("users", "users", None),
            ("interface_name", "interface-name", None),
            ("routing_mark", "routing-mark", None),
        ):
            current = getattr(node, attr)
            original = node.raw.get(key, default)
            if current == original:
                continue
            if current is None or current == default:
                output.pop(key, None)
            else:
                output[key] = copy.deepcopy(current)
        return output


class StashEmitter(ClashEmitter):
    """Stash YAML emitter using the shared Clash-family document path."""

    def __init__(self):
        super().__init__(platform="stash")

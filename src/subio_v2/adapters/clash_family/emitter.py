import copy
from typing import Any, Dict, List

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.base import BaseEmitter
from subio_v2.adapters.clash_family.dialect import post_descriptor_emit
from subio_v2.adapters.clash_family.stash import post_stash_emit
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
            encoded = self.encode_node(node, self._emit_node)
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
        return EmissionResult(
            content={"proxies": proxies},
            supported_nodes=emitted_nodes,
            issues=issues,
            extras={"template_context": self.template_context(emitted_nodes)},
        )

    def _emit_node(
        self, node: Node
    ) -> tuple[Dict[str, Any] | None, tuple[str, ...]]:
        if isinstance(node, SourcePassthroughNode):
            return self._emit_source_passthrough(node), ()
        target_codec = protocol_registry.target_codec(
            self.target_context.dialect, node.type
        )
        if target_codec is None:
            return None, ()
        proxy = target_codec.emit(node, self.target_context)
        return self._post_descriptor_emit(proxy, node)

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

    def _post_descriptor_emit(
        self, proxy: Dict[str, Any], node: Node
    ) -> tuple[Dict[str, Any], tuple[str, ...]]:
        return post_descriptor_emit(proxy, node, self.target_context, self.platform)


class StashEmitter(ClashEmitter):
    """Stash YAML emitter using the shared Clash-family document path."""

    def __init__(self):
        super().__init__(platform="stash")

    def _post_descriptor_emit(
        self, proxy: dict[str, Any], node: Node
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        output, dropped = super()._post_descriptor_emit(proxy, node)
        output, stash_dropped = post_stash_emit(output, node)
        return output, tuple(sorted({*dropped, *stash_dropped}))

from typing import Any

from subio_v2.adapters.base import BaseEmitter
from subio_v2.adapters.singbox.endpoint import (
    SINGBOX_ENDPOINT_CODECS,
    encode_endpoint,
)
from subio_v2.adapters.singbox.outbound import (
    SINGBOX_OUTBOUND_CODECS,
    encode_outbound,
)
from subio_v2.core.nodes import Node
from subio_v2.core.results import EmissionResult, IssueSeverity


class SingBoxEmitter(BaseEmitter):
    platform = "sing-box"

    def emit_result(self, nodes: list[Node]) -> EmissionResult[dict[str, Any]]:
        issues = []
        outbounds: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        accepted_indices: set[int] = set()
        emitted_tags: set[str] = set()
        outbound_tags: set[str] = set()

        outbound_nodes = [
            (index, node)
            for index, node in enumerate(nodes)
            if node.type in SINGBOX_OUTBOUND_CODECS
        ]
        endpoint_nodes = [
            (index, node)
            for index, node in enumerate(nodes)
            if node.type in SINGBOX_ENDPOINT_CODECS
        ]
        unsupported_nodes = [
            (index, node)
            for index, node in enumerate(nodes)
            if node.type not in SINGBOX_OUTBOUND_CODECS
            and node.type not in SINGBOX_ENDPOINT_CODECS
        ]

        for index, node in outbound_nodes:
            encoded = self.encode_node(node, encode_outbound)
            issues.extend(encoded.issues)
            if encoded.supported_node is None or encoded.content is None:
                continue
            tag = encoded.content["tag"]
            if tag in emitted_tags:
                issues.append(self._duplicate_tag_issue(node))
                continue
            outbounds.append(encoded.content)
            emitted_tags.add(tag)
            outbound_tags.add(tag)
            accepted_indices.add(index)

        for index, node in endpoint_nodes:
            encoded = self.encode_node(node, encode_endpoint)
            issues.extend(encoded.issues)
            if encoded.supported_node is None or encoded.content is None:
                continue
            tag = encoded.content["tag"]
            if tag in emitted_tags:
                issues.append(self._duplicate_tag_issue(node))
                continue
            detour = encoded.content.get("detour")
            if detour is not None and detour not in outbound_tags:
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Endpoint detour '{detour}' does not reference an emitted outbound tag",
                        field="dialer_proxy",
                        code="conversion.invalid-endpoint-detour",
                    )
                )
                continue
            endpoints.append(encoded.content)
            emitted_tags.add(tag)
            accepted_indices.add(index)

        for _, node in unsupported_nodes:
            encoded = self.encode_node(node, encode_outbound)
            issues.extend(encoded.issues)

        candidates = [node for index, node in enumerate(nodes) if index in accepted_indices]
        retained, relation_issues = self.retain_dialer_indices(nodes, candidates)
        issues.extend(relation_issues)
        supported_nodes = [node for index, node in enumerate(candidates) if index in retained]
        final_tags = {node.name for node in supported_nodes}
        return EmissionResult(
            content={
                "outbounds": [item for item in outbounds if item["tag"] in final_tags],
                "endpoints": [item for item in endpoints if item["tag"] in final_tags],
            },
            supported_nodes=supported_nodes,
            issues=issues,
        )

    def _duplicate_tag_issue(self, node: Node):
        return self.issue_for_node(
            node,
            IssueSeverity.ERROR,
            f"Duplicate sing-box tag '{node.name}'",
            field="name",
            code="conversion.duplicate-node-name",
        )

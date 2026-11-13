import json
from typing import Any

from subio_v2.adapters.base import BaseEmitter
from subio_v2.core.errors import TemplateRenderError
from subio_v2.core.nodes import Node
from subio_v2.core.results import EmissionResult, IssueSeverity


def serialize_nodes(content: dict[str, Any], template: bool) -> str:
    return json.dumps(content, ensure_ascii=False, indent=2) + "\n"


def template_fragment(rendered: str, key: str) -> str:
    return json.dumps(json.loads(rendered)[key], ensure_ascii=False)


def validate_template(content: str, path: str) -> None:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise TemplateRenderError(
            f"Rendered sing-box template '{path}' is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise TemplateRenderError(
            f"Rendered sing-box template '{path}' must be a JSON object"
        )


class SingBoxEmitter(BaseEmitter):
    platform = "sing-box"

    def emit_result(self, nodes: list[Node]) -> EmissionResult[dict[str, Any]]:
        issues = []
        outbounds: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        accepted_indices: set[int] = set()
        emitted_tags: set[str] = set()
        outbound_tags: set[str] = set()

        sections = {"outbounds": [], "endpoints": [], None: []}
        for index, node in enumerate(nodes):
            binding = self._conversion.target.codecs.get(node.type)
            sections[binding.section if binding else None].append((index, node))
        outbound_nodes = sections["outbounds"]
        endpoint_nodes = sections["endpoints"]
        unsupported_nodes = sections[None]

        for index, node in outbound_nodes:
            encoded = self.encode_node(node)
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
            encoded = self.encode_node(node)
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
            encoded = self.encode_node(node)
            issues.extend(encoded.issues)

        candidates = [
            node for index, node in enumerate(nodes) if index in accepted_indices
        ]
        retained, relation_issues = self.retain_dialer_indices(nodes, candidates)
        issues.extend(relation_issues)
        supported_nodes = [
            node for index, node in enumerate(candidates) if index in retained
        ]
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

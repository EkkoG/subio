import copy
from typing import Any, Dict

import yaml

import subio_v2.protocols as protocol_registry
from subio_v2.clash.dialect import pre_descriptor_normalize
from subio_v2.conversion import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.dialect import DialectContext
from subio_v2.formats import normalize_format
from subio_v2.model.nodes import SourcePassthroughNode
from subio_v2.model.records import NodeRecord


class ClashParser:
    def __init__(self, context: DialectContext | None = None):
        context = context or DialectContext("mihomo", "yaml")
        self.context = DialectContext(
            normalize_format(context.dialect), context.format
        )

    def parse_result(self, content: Any) -> ParseResult:
        if isinstance(content, str):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise ValueError(f"YAML parse error: {e}") from e
        elif isinstance(content, dict):
            data = content
        else:
            raise ValueError("Invalid content type for ClashParser")

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid Clash config format: Expected dict, got {type(data)}. "
                f"Content preview: {str(content)[:100]}"
            )

        proxies = data.get("proxies")
        if proxies is None:
            raise ValueError("Clash config missing 'proxies' key")
        if not isinstance(proxies, list):
            raise ValueError("'proxies' is not a list")

        nodes = []
        issues: list[ConversionIssue] = []
        for index, proxy in enumerate(proxies):
            if not isinstance(proxy, dict):
                issues.append(
                    ConversionIssue(
                        severity=IssueSeverity.ERROR,
                        node=None,
                        protocol=None,
                        source=None,
                        target=None,
                        field=f"proxies[{index}]",
                        message="Clash proxy entry must be an object",
                        stage="parse",
                        code="parse.invalid-entry",
                    )
                )
                continue
            try:
                node = self._parse_node(proxy)
            except Exception as exc:
                issues.append(
                    ConversionIssue(
                        severity=IssueSeverity.ERROR,
                        node=proxy.get("name"),
                        protocol=str(proxy.get("type")) if proxy.get("type") else None,
                        source=None,
                        target=None,
                        field=f"proxies[{index}]",
                        message=f"Failed to parse Clash proxy: {exc}",
                        stage="parse",
                        code="parse.node",
                    )
                )
                continue
            if node:
                nodes.append(node)
        return ParseResult(nodes=nodes, issues=issues)

    def _parse_node(self, data: Dict[str, Any]):
        node_type = data.get("type")
        if not node_type:
            return None

        desc = protocol_registry.by_clash_type(str(node_type))
        if not desc:
            node = SourcePassthroughNode(
                name=data.get("name", "Unknown"),
                record=NodeRecord(
                    opaque_type=str(node_type), opaque_raw=copy.deepcopy(data)
                ),
                server=data.get("server"),
                port=data.get("port"),
                udp=data.get("udp", True),
                ip_version=data.get("ip-version"),
                tfo=data.get("tfo", False),
                mptcp=data.get("mptcp", False),
                dialer_proxy=data.get("dialer-proxy"),
                users=data.get("users"),
                interface_name=data.get("interface-name"),
                routing_mark=data.get("routing-mark"),
            )
            node.source_context = self.context
            return node
        if not desc.supports_dialect(self.context.dialect):
            raise ValueError(
                f"Known proxy type '{node_type}' is not supported by "
                f"the {self.context.dialect} input dialect"
            )
        normalized = pre_descriptor_normalize(data, self.context)
        return desc.parse_clash(normalized, self.context)

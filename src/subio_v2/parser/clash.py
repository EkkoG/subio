import sys
from typing import Any, Dict, List

import yaml

import subio_v2.protocols as protocol_registry
from subio_v2.clash.dialect import pre_descriptor_normalize
from subio_v2.conversion import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.dialect import DialectContext
from subio_v2.model.nodes import Protocol
from subio_v2.parser.base import BaseParser
from subio_v2.utils.logger import logger


class ClashParser(BaseParser):
    def __init__(self, context: DialectContext | None = None):
        self.context = context or DialectContext("mihomo", "yaml")

    def parse(self, content: Any) -> List:
        try:
            return self.parse_result(content).nodes
        except ValueError as exc:
            logger.error(str(exc))
            sys.exit(1)

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
                        target="ir",
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
                        target="ir",
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
        data = pre_descriptor_normalize(data, self.context)
        node_type = data.get("type")
        if not node_type:
            return None

        desc = protocol_registry.by_clash_type(node_type)
        if not desc:
            desc = protocol_registry.get(Protocol.CLASH_UNKNOWN)
            logger.warning(
                f"Unknown Clash proxy type '{node_type}' preserved for Mihomo output"
            )
        return desc.parse_clash(data, self.context)

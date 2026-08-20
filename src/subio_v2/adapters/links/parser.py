import base64
import urllib.parse
from typing import Any

from subio_v2.adapters.links import codecs as links
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node
from subio_v2.core.results import ConversionIssue, IssueSeverity, ParseResult


class V2RayNParser:
    def parse_result(self, content: Any) -> ParseResult:
        if not isinstance(content, str):
            raise ValueError("Invalid content type for V2RayNParser")  # noqa: TRY004

        try:
            lines = base64.b64decode(content).decode("utf-8").splitlines()
        except Exception:  # noqa: BLE001
            lines = content.splitlines()

        nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line:
                continue
            node = links.parse_url(line)
            if node is not None:
                node.source_context = DialectContext("v2rayn", "text")
                nodes.append(node)
                continue
            scheme = line.partition("://")[0] or None
            fragment = urllib.parse.urlparse(line).fragment
            issues.append(
                ConversionIssue(
                    severity=IssueSeverity.ERROR,
                    node=urllib.parse.unquote(fragment) if fragment else None,
                    protocol=scheme,
                    source=None,
                    target=None,
                    field=f"lines[{index}]",
                    message="Failed to parse v2rayN subscription link",
                    stage="parse",
                    code="parse.link",
                )
            )
        return ParseResult(nodes=nodes, issues=issues)

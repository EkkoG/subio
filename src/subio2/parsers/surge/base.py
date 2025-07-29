"""Surge parser base class."""

import re
from typing import List, Optional
from ...core.registry import parser_registry
from ...models.node import Proxy
from ..base import BaseParser


@parser_registry.decorator("surge")
class SurgeParser(BaseParser):
    """Parser for Surge configuration format."""

    def __init__(self):
        super().__init__()
        # Trigger protocol registration
        from . import protocols  # noqa

    def parse(self, content: str) -> List[Proxy]:
        """Parse Surge configuration."""
        nodes = []

        # Find [Proxy] section
        proxy_section = self._extract_section(content, "Proxy")
        if not proxy_section:
            return nodes

        # Parse each line in the proxy section
        for line in proxy_section.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            node = self._parse_proxy_line(line)
            if node:
                nodes.append(node)

        return nodes

    def _extract_section(self, content: str, section_name: str) -> Optional[str]:
        """Extract a section from Surge config."""
        # Pattern to match [SectionName] ... next section or EOF
        pattern = rf"\[{section_name}\](.*?)(?=\[|\Z)"
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _parse_proxy_line(self, line: str) -> Optional[Proxy]:
        """Parse a single proxy line."""
        try:
            # Format: ProxyName = protocol, server, port, ...params
            if "=" not in line:
                return None

            name, config = line.split("=", 1)
            name = name.strip()
            config = config.strip()

            # Parse config parts
            parts = [p.strip() for p in config.split(",")]
            if len(parts) < 3:
                return None

            protocol = parts[0].lower()
            server = parts[1]
            port = int(parts[2])

            # Import protocol parsers
            from .protocols.registry import surge_protocol_registry

            # Get parser for this protocol
            parser = surge_protocol_registry.get_parser(protocol)
            if parser:
                return parser(name, server, port, parts[3:])
            else:
                print(f"No parser for Surge protocol: {protocol}")
                return None

        except Exception as e:
            print(f"Failed to parse Surge proxy line: {line}, error: {e}")
            return None

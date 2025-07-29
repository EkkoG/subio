"""V2rayN parser base class."""

from typing import List, Dict, Optional, Callable
from urllib.parse import urlparse
from ...core.registry import parser_registry
from ...models.node import Proxy
from ..base import BaseParser


@parser_registry.decorator("v2rayn")
class V2rayNParser(BaseParser):
    """Parser for V2rayN share format."""

    def __init__(self):
        super().__init__()
        self.protocol_parsers: Dict[str, Callable] = {}
        self._register_protocols()

    def _register_protocols(self):
        """Register protocol-specific parsers."""
        try:
            from .protocols import shadowsocks, vmess, trojan, vless, http

            self.protocol_parsers["ss"] = shadowsocks.parse
            self.protocol_parsers["vmess"] = vmess.parse
            self.protocol_parsers["trojan"] = trojan.parse
            self.protocol_parsers["vless"] = vless.parse
            self.protocol_parsers["http"] = http.parse

        except ImportError as e:
            print(f"Warning: Failed to import V2rayN protocol parsers: {e}")

    def parse(self, content: str) -> List[Proxy]:
        """Parse V2rayN share URLs."""
        nodes = []

        # Split content by lines and process each URL
        lines = content.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            node = self._parse_url(line)
            if node:
                nodes.append(node)

        return nodes

    def _parse_url(self, url: str) -> Optional[Proxy]:
        """Parse a single share URL."""
        try:
            parsed = urlparse(url)
            protocol = parsed.scheme.lower()

            if protocol in self.protocol_parsers:
                return self.protocol_parsers[protocol](url)

            print(f"Unsupported protocol: {protocol}")
            return None

        except Exception as e:
            print(f"Failed to parse URL {url}: {e}")
            return None

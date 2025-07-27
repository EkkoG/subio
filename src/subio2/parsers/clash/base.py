"""Clash parser base class."""
import yaml
from typing import List, Dict, Any, Optional, Callable
from ...core.registry import parser_registry
from ...models import Node
from ..base import BaseParser


@parser_registry.decorator('clash')
@parser_registry.decorator('clash-meta')
@parser_registry.decorator('stash')
class ClashParser(BaseParser):
    """Parser for Clash YAML format."""
    
    supported_formats = ['clash', 'clash-meta', 'stash']
    
    def __init__(self):
        super().__init__()
        self._register_protocols()
    
    def _register_protocols(self):
        """Register protocol-specific parsers by importing modules."""
        try:
            # Import all protocol modules to trigger auto-registration
            from .protocols import shadowsocks, vmess, trojan, vless, hysteria, http, socks5
            from .protocols.registry import clash_protocol_registry
            
            # Store reference to registry
            self.protocol_registry = clash_protocol_registry
            
        except ImportError as e:
            print(f"Warning: Failed to import protocol parsers: {e}")
            self.protocol_registry = None
    
    def parse(self, content: str) -> List[Node]:
        """Parse Clash YAML configuration."""
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return []
            
            proxies = data.get('proxies', [])
            nodes = []
            
            for proxy in proxies:
                node = self._parse_proxy(proxy)
                if node:
                    nodes.append(node)
            
            return nodes
        except Exception:
            return []
    
    def _parse_proxy(self, proxy: Dict[str, Any]) -> Optional[Node]:
        """Parse a single proxy configuration."""
        try:
            proxy_type = proxy.get('type', '').lower()
            
            # Use protocol-specific parser if available
            if self.protocol_registry:
                parser_func = self.protocol_registry.get_parser(proxy_type)
                if parser_func:
                    return parser_func(proxy)
            
            # Fallback to generic parsing for unsupported types
            print(f"Unsupported node type: {proxy_type}")
            return None
            
        except Exception as e:
            print(f"Failed to parse proxy {proxy.get('name', 'Unknown')}: {e}")
            return None
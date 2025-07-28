"""SubIO protocol parsers."""
from typing import Dict, Any, Optional, Callable
from ....models.node import CompositeNode

# Protocol parser registry
PROTOCOL_PARSERS: Dict[str, Callable[[Dict[str, Any]], Optional[CompositeNode]]] = {}

def register_parser(protocol_type: str):
    """Decorator to register a protocol parser."""
    def decorator(parser_func: Callable[[Dict[str, Any]], Optional[CompositeNode]]):
        PROTOCOL_PARSERS[protocol_type] = parser_func
        return parser_func
    return decorator

def parse_node(node_data: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse a node using the appropriate protocol parser."""
    if not isinstance(node_data, dict):
        return None
    
    # Get protocol type
    node_type = node_data.get('type', '').lower()
    
    # Find parser
    parser = PROTOCOL_PARSERS.get(node_type)
    if not parser:
        return None
    
    return parser(node_data)

# Import all protocol parsers to register them
from . import shadowsocks
from . import http
from . import socks5
from . import trojan
from . import vmess
from . import vless
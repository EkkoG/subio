"""Mieru protocol parser for Clash."""
from typing import Dict, Any, Optional
from ....models.node import Proxy, MieruProtocol
from .registry import register_clash_parser


@register_clash_parser('mieru')
def parse_mieru(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse Mieru proxy configuration."""
    try:
        protocol = MieruProtocol(
            username=data.get('username', ''),
            password=data.get('password', ''),
            transport=data.get('transport', 'TCP'),
            multiplexing=data.get('multiplexing', 'MULTIPLEXING_LOW'),
            port_range=data.get('port-range')
        )
        
        node = Proxy(
            name=data.get('name', 'mieru'),
            server=data.get('server', ''),
            port=data.get('port', 2999),
            protocol=protocol
        )
        
        # Mieru supports UDP over TCP
        node.extra['udp'] = data.get('udp', True)
        
        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"Mieru validation error: {e}")
            return None
        
        return node
    except Exception as e:
        print(f"Failed to parse Mieru proxy: {e}")
        return None
"""Shadowsocks renderer for Surge format."""
from ....models.node import Proxy, ShadowsocksProtocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register('ss', 'shadowsocks')
def render(node: Proxy) -> str:
    """Render Shadowsocks node to Surge format."""
    protocol = node.protocol
    if not isinstance(protocol, ShadowsocksProtocol):
        return ""
    
    # Basic format: ProxyName = shadowsocks, server, port, encrypt-method=, password=
    parts = [
        node.name,
        'shadowsocks',
        node.server,
        str(node.port),
        f'encrypt-method={protocol.method}',
        f'password={protocol.password}'
    ]
    
    # Add UDP relay if specified
    if node.extra and node.extra.get('udp'):
        parts.append('udp-relay=true')
    
    # Add obfs if present
    if hasattr(protocol, 'plugin') and protocol.plugin == 'obfs-local':
        opts = protocol.plugin_opts or {}
        mode = opts.get('mode', 'http')
        parts.append(f'obfs={mode}')
        if 'host' in opts:
            parts.append(f'obfs-host={opts["host"]}')
    
    return f"{parts[0]} = {', '.join(parts[1:])}"
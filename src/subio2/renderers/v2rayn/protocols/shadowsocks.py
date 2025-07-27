"""Shadowsocks renderer for V2rayN format."""
import base64
from urllib.parse import quote, urlencode
from ....models.node_composite import CompositeNode, ShadowsocksProtocol
from .registry import v2rayn_protocol_registry


@v2rayn_protocol_registry.register('ss', 'shadowsocks')
def render(node: CompositeNode) -> str:
    """Render Shadowsocks node to V2rayN URL format."""
    protocol = node.protocol
    if not isinstance(protocol, ShadowsocksProtocol):
        return ""
    
    # Build ss URL: ss://base64(method:password)@server:port#name
    auth = f"{protocol.method}:{protocol.password}"
    encoded_auth = base64.b64encode(auth.encode()).decode().rstrip('=')
    
    # Build URL
    url = f"ss://{encoded_auth}@{node.server}:{node.port}"
    
    # Add plugin parameters if present
    if hasattr(protocol, 'plugin') and protocol.plugin:
        params = {}
        plugin_str = protocol.plugin
        if hasattr(protocol, 'plugin_opts') and protocol.plugin_opts:
            # Build plugin string like "obfs-local;obfs=tls;obfs-host=example.com"
            plugin_parts = [plugin_str]
            for k, v in protocol.plugin_opts.items():
                plugin_parts.append(f"{k}={v}")
            plugin_str = ';'.join(plugin_parts)
        params['plugin'] = plugin_str
        url += '?' + urlencode(params)
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url
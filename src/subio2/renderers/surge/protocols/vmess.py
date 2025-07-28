"""VMess renderer for Surge format."""
from ....models.node import Proxy, VmessProtocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register('vmess')
def render(node: Proxy) -> str:
    """Render VMess node to Surge format."""
    protocol = node.protocol
    if not isinstance(protocol, VmessProtocol):
        return ""
    
    # Basic format: ProxyName = vmess, server, port, username=uuid
    parts = [
        node.name,
        'vmess',
        node.server,
        str(node.port),
        f'username={protocol.uuid}'
    ]
    
    # Add WebSocket if present
    if node.transport and node.transport.type == 'ws':
        parts.append('ws=true')
        if hasattr(node.transport, 'ws') and node.transport.ws:
            ws = node.transport.ws
            if ws.path and ws.path != '/':
                parts.append(f'ws-path={ws.path}')
            if ws.headers:
                # Format headers as "Key:Value|Key2:Value2"
                headers_str = '|'.join([f'{k}:{v}' for k, v in ws.headers.items()])
                parts.append(f'ws-headers={headers_str}')
    
    # Add TLS if enabled
    if node.tls and node.tls.enabled:
        parts.append('tls=true')
    
    return f"{parts[0]} = {', '.join(parts[1:])}"
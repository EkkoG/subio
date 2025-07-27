"""VMess URL parser for V2rayN format."""
import base64
import json
from typing import Optional
from urllib.parse import unquote
from ....models.node_composite import CompositeNode, VmessProtocol, TLSConfig, Transport, WebSocketTransport


def parse(url: str) -> Optional[CompositeNode]:
    """Parse VMess URL: vmess://base64(json)"""
    try:
        # Remove vmess:// prefix
        encoded = url.replace('vmess://', '')
        
        # Decode base64
        decoded = base64.b64decode(encoded + '==').decode('utf-8')
        
        # Parse JSON
        data = json.loads(decoded)
        
        # Extract required fields
        server = data.get('add')
        port = int(data.get('port', 0))
        uuid = data.get('id')
        name = data.get('ps', f"{server}:{port}")
        
        if not all([server, port, uuid]):
            return None
        
        # Create protocol config
        protocol = VmessProtocol(
            uuid=uuid,
            alter_id=int(data.get('aid', 0)),
            security=data.get('scy', 'auto')
        )
        
        # Create node
        node = CompositeNode(
            name=unquote(name),
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS
        if data.get('tls') == 'tls':
            node.tls = TLSConfig(
                enabled=True,
                sni=data.get('sni'),
                skip_cert_verify=data.get('skip-cert-verify', False)
            )
        
        # Handle transport
        net = data.get('net', 'tcp')
        if net != 'tcp':
            transport = Transport(type=net)
            
            if net == 'ws':
                transport.ws = WebSocketTransport(
                    path=data.get('path', '/'),
                    headers={'Host': data.get('host', '')} if data.get('host') else {}
                )
            
            node.transport = transport
        
        return node
        
    except Exception as e:
        print(f"Failed to parse VMess URL: {e}")
        return None
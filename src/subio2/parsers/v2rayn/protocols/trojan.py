"""Trojan URL parser for V2rayN format."""
from typing import Optional
from urllib.parse import parse_qs, urlparse, unquote
from ....models.node import CompositeNode, TrojanProtocol, TLSConfig, Transport, WebSocketTransport, GRPCTransport


def parse(url: str) -> Optional[CompositeNode]:
    """Parse Trojan URL: trojan://password@server:port?sni=xxx&type=ws&path=/&host=xxx"""
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'trojan':
            return None
        
        # Extract password from username part
        password = unquote(parsed.username or '')
        if not password:
            return None
        
        # Extract server and port
        server = parsed.hostname
        port = parsed.port
        if not server or not port:
            return None
        
        # Parse query parameters
        params = parse_qs(parsed.query)
        
        # Extract name (default to server:port)
        name = params.get('remarks', [f"{server}:{port}"])[0]
        name = unquote(name)
        
        # Create protocol config
        protocol = TrojanProtocol(password=password)
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS (Trojan always uses TLS)
        node.tls = TLSConfig(
            enabled=True,
            sni=params.get('sni', [None])[0],
            skip_cert_verify=params.get('allowInsecure', ['0'])[0] == '1'
        )
        
        # Handle transport
        net_type = params.get('type', ['tcp'])[0]
        if net_type != 'tcp':
            transport = Transport(type=net_type)
            
            if net_type == 'ws':
                transport.ws = WebSocketTransport(
                    path=params.get('path', ['/'])[0],
                    headers={'Host': params.get('host', [''])[0]} if params.get('host') else {}
                )
            elif net_type == 'grpc':
                transport.grpc = GRPCTransport(
                    service_name=params.get('serviceName', [''])[0]
                )
            
            node.transport = transport
        
        return node
        
    except Exception as e:
        print(f"Failed to parse Trojan URL: {e}")
        return None
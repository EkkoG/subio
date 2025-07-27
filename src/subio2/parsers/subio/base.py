"""SubIO native format parser."""
import toml
import yaml
import json
import json5
from typing import List, Dict, Any, Optional
from ...core.registry import parser_registry
from ...models.node_composite import (
    CompositeNode, ShadowsocksProtocol, HttpProtocol, 
    Socks5Protocol, TrojanProtocol, VmessProtocol, 
    VlessProtocol, WebSocketTransport, GRPCTransport,
    BasicAuth, TLSConfig
)
from ..base import BaseParser


@parser_registry.decorator('subio')
class SubIOParser(BaseParser):
    """Parser for SubIO native format (TOML/YAML/JSON)."""
    
    def parse(self, content: str) -> List[CompositeNode]:
        """Parse SubIO native format."""
        try:
            # Try to detect format
            data = self._parse_content(content)
            
            if not isinstance(data, dict):
                return []
            
            # SubIO format has 'nodes' key
            nodes_data = data.get('nodes', [])
            nodes = []
            
            for node_data in nodes_data:
                node = self._parse_node(node_data)
                if node:
                    nodes.append(node)
            
            return nodes
        except Exception as e:
            print(f"Error parsing SubIO content: {e}")
            return []
    
    def _parse_content(self, content: str) -> Dict[str, Any]:
        """Try to parse content in different formats."""
        # Try TOML first
        try:
            return toml.loads(content)
        except:
            pass
        
        # Try YAML
        try:
            return yaml.safe_load(content)
        except:
            pass
        
        # Try JSON5
        try:
            return json5.loads(content)
        except:
            pass
        
        # Try JSON
        try:
            return json.loads(content)
        except:
            pass
        
        raise ValueError("Unable to parse content as TOML, YAML, JSON5 or JSON")
    
    def _parse_node(self, node_data: Dict[str, Any]) -> Optional[CompositeNode]:
        """Parse a single node."""
        if not isinstance(node_data, dict):
            return None
        
        # Get basic info
        name = node_data.get('name', 'Unnamed')
        server = node_data.get('server', node_data.get('address'))
        port = node_data.get('port', 443)
        
        if not server:
            return None
        
        # Get protocol type
        node_type = node_data.get('type', '').lower()
        
        # Create protocol based on type
        protocol = None
        
        if node_type == 'shadowsocks' or node_type == 'ss':
            protocol = ShadowsocksProtocol(
                method=node_data.get('method', node_data.get('cipher', 'aes-256-gcm')),
                password=node_data.get('password', '')
            )
        
        elif node_type == 'socks5' or node_type == 'socks':
            protocol = Socks5Protocol(
                tls=node_data.get('tls', False)
            )
        
        elif node_type == 'http':
            protocol = HttpProtocol(
                tls=node_data.get('tls', False)
            )
        
        elif node_type == 'trojan':
            protocol = TrojanProtocol(
                password=node_data.get('password', '')
            )
        
        elif node_type == 'vmess':
            protocol = VmessProtocol(
                uuid=node_data.get('uuid', ''),
                security=node_data.get('security', node_data.get('cipher', 'auto')),
                alter_id=node_data.get('alter_id', node_data.get('alterId', 0))
            )
        
        elif node_type == 'vless':
            protocol = VlessProtocol(
                uuid=node_data.get('uuid', ''),
                flow=node_data.get('flow')
            )
        
        else:
            return None
        
        if not protocol:
            return None
        
        # Create composite node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Add auth for HTTP/SOCKS5
        if node_type in ['http', 'socks5', 'socks']:
            username = node_data.get('username')
            password = node_data.get('password')
            if username and password:
                node.auth = BasicAuth(username=username, password=password)
        
        # Add transport if specified
        transport_type = node_data.get('transport', node_data.get('network'))
        if transport_type:
            transport = self._parse_transport(transport_type, node_data)
            if transport:
                node.transport = transport
        
        # Add TLS config
        if node_data.get('tls'):
            node.tls = TLSConfig(
                enabled=True,
                skip_cert_verify=node_data.get('skip_cert_verify', node_data.get('skip-cert-verify', False)),
                sni=node_data.get('sni', node_data.get('servername'))
            )
        
        # Add extra metadata
        if node_data.get('udp'):
            node.extra['udp'] = True
        
        return node
    
    def _parse_transport(self, transport_type: str, node_data: Dict[str, Any]) -> Optional[Any]:
        """Parse transport configuration."""
        if transport_type == 'ws' or transport_type == 'websocket':
            return WebSocketTransport(
                path=node_data.get('ws_path', node_data.get('path', '/')),
                headers=node_data.get('ws_headers', node_data.get('headers', {}))
            )
        
        elif transport_type == 'grpc':
            return GRPCTransport(
                service_name=node_data.get('grpc_service_name', node_data.get('service_name', ''))
            )
        
        return None
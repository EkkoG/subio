"""Stash renderer - extends Clash renderer with Stash-specific protocol handling."""
from typing import Dict, Any, Optional
from ...core.registry import renderer_registry
from ...models.node import CompositeNode, HysteriaProtocol, Hysteria2Protocol
from ..clash.base import ClashRenderer


@renderer_registry.decorator('stash')
class StashRenderer(ClashRenderer):
    """Renderer for Stash format - extends Clash with Stash-specific protocols."""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        # Don't call parent __init__ yet, we need to set renderer_type first
        self.renderer_type = 'stash'
        super().__init__(template_dir, snippet_dir)
    
    def _register_protocols(self):
        """Register protocol handlers including Stash-specific ones."""
        # First register all Clash protocols
        super()._register_protocols()
        
        # Then override or add Stash-specific protocols
        from .protocols import hysteria, hysteria2
        # The decorators in protocol files will auto-register them
    
    def _get_protocol_registry(self):
        """Get the appropriate protocol registry for this renderer."""
        # Use stash-specific registry if we create one, 
        # otherwise fallback to clash registry
        from ..clash.protocols.registry import clash_protocol_registry
        return clash_protocol_registry
    
    def render_node(self, node: CompositeNode) -> Dict[str, Any]:
        """Render a single node to Stash format."""
        # For most protocols, use Clash rendering
        result = super().render_node(node)
        
        # Handle Stash-specific modifications
        if isinstance(node.protocol, HysteriaProtocol):
            # Stash might have different field names or format for Hysteria
            result = self._render_hysteria_stash(node, result)
        elif isinstance(node.protocol, Hysteria2Protocol):
            # Stash-specific Hysteria2 handling
            result = self._render_hysteria2_stash(node, result)
        
        # Add any Stash-specific fields
        if self.renderer_type == 'stash':
            # Example: Stash might not need certain fields
            result.pop('ip-version', None)
            result.pop('mptcp', None)
        
        return result
    
    def _render_hysteria_stash(self, node: CompositeNode, base_result: Dict[str, Any]) -> Dict[str, Any]:
        """Render Hysteria protocol in Stash-specific format."""
        # Example: Stash might use different field names
        protocol = node.protocol
        
        # Stash-specific Hysteria format
        result = {
            'name': node.name,
            'type': 'hysteria',
            'server': node.server,
            'port': node.port,
            # Stash might use different field names
            'auth-str': protocol.auth_str,
            'protocol': protocol.protocol,
            'up': protocol.up_mbps,
            'down': protocol.down_mbps,
        }
        
        if protocol.obfs:
            result['obfs'] = protocol.obfs
        
        if node.tls:
            result['sni'] = node.tls.sni or node.server
            result['skip-cert-verify'] = node.tls.skip_cert_verify
            if node.tls.fingerprint:
                result['fingerprint'] = node.tls.fingerprint
        
        return result
    
    def _render_hysteria2_stash(self, node: CompositeNode, base_result: Dict[str, Any]) -> Dict[str, Any]:
        """Render Hysteria2 protocol in Stash-specific format."""
        protocol = node.protocol
        
        # Stash-specific Hysteria2 format
        result = {
            'name': node.name,
            'type': 'hysteria2',
            'server': node.server,
            'port': node.port,
            'password': protocol.password,
        }
        
        if protocol.obfs:
            result['obfs'] = protocol.obfs
            if protocol.obfs_password:
                result['obfs-password'] = protocol.obfs_password
        
        return result
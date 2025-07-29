"""Protocol renderer registry for auto-registration."""
from typing import Dict, Callable, List
from functools import wraps


class ProtocolRendererRegistry:
    """Registry for protocol renderers with auto-registration."""
    
    def __init__(self):
        self._renderers: Dict[str, Callable] = {}
    
    def register(self, *protocol_types: str):
        """Decorator to register protocol renderer functions."""
        def decorator(func: Callable):
            for ptype in protocol_types:
                self._renderers[ptype.lower()] = func
            return func
        return decorator
    
    def get_renderer(self, protocol_type: str) -> Callable:
        """Get renderer function for a protocol type."""
        return self._renderers.get(protocol_type.lower())
    
    def get_supported_protocols(self) -> List[str]:
        """Get list of supported protocol types."""
        return list(self._renderers.keys())
    
    def get_all_renderers(self) -> Dict[str, Callable]:
        """Get all registered renderers."""
        return self._renderers.copy()


# Global registry instance for Clash renderers
clash_renderer_registry = ProtocolRendererRegistry()

# Alias for backward compatibility
register_clash_renderer = clash_renderer_registry.register
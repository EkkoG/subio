"""Registry for DAE protocol renderers."""
from typing import Callable, Dict, Optional
from ....models.node import CompositeNode


class DAEProtocolRegistry:
    """Registry for DAE protocol renderers with auto-registration."""
    
    def __init__(self):
        self._renderers: Dict[str, Callable] = {}
    
    def register(self, *protocol_names: str):
        """Decorator to register protocol renderer functions."""
        def decorator(func: Callable):
            for name in protocol_names:
                self._renderers[name.lower()] = func
            return func
        return decorator
    
    def get_renderer(self, protocol_type: str) -> Optional[Callable]:
        """Get renderer function for a protocol type."""
        return self._renderers.get(protocol_type.lower())


# Global registry instance
dae_protocol_registry = DAEProtocolRegistry()
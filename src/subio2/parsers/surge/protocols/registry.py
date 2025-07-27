"""Registry for Surge protocol parsers."""
from typing import Callable, Dict, Optional, List
from ....models.node_composite import CompositeNode


class SurgeProtocolRegistry:
    """Registry for Surge protocol parsers with auto-registration."""
    
    def __init__(self):
        self._parsers: Dict[str, Callable] = {}
    
    def register(self, *protocol_names: str):
        """Decorator to register protocol parser functions."""
        def decorator(func: Callable):
            for name in protocol_names:
                self._parsers[name.lower()] = func
            return func
        return decorator
    
    def get_parser(self, protocol_type: str) -> Optional[Callable]:
        """Get parser function for a protocol type."""
        return self._parsers.get(protocol_type.lower())


# Global registry instance
surge_protocol_registry = SurgeProtocolRegistry()
"""Protocol parser registry for auto-registration."""
from typing import Dict, Callable, List
from functools import wraps


class ProtocolRegistry:
    """Registry for protocol parsers with auto-registration."""
    
    def __init__(self):
        self._parsers: Dict[str, Callable] = {}
    
    def register(self, *protocol_names: str):
        """Decorator to register protocol parser functions."""
        def decorator(func: Callable):
            for name in protocol_names:
                self._parsers[name.lower()] = func
            return func
        return decorator
    
    def get_parser(self, protocol: str) -> Callable:
        """Get parser function for a protocol."""
        return self._parsers.get(protocol.lower())
    
    def get_supported_protocols(self) -> List[str]:
        """Get list of supported protocols."""
        return list(self._parsers.keys())
    
    def get_all_parsers(self) -> Dict[str, Callable]:
        """Get all registered parsers."""
        return self._parsers.copy()


# Global registry instance for Clash parsers
clash_protocol_registry = ProtocolRegistry()